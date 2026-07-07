"""
SeedSigner Views for Legacy Encryption

Flow:
  MainMenu → LegacyMainMenuView
    ├── Encrypt: LegacyEncryptInputMethodView
    │    ├── Scan Seed QR → LegacyEncryptScanSeedView
    │    │                → EnterBenefactorKey → EnterBeneficiaryKey
    │    │                → ConfirmEncrypt → EncryptingView → ShowEncryptedQRView
    │    └── Enter Manually → LegacyManualSeedWordCountView
    │                       → LegacyEnterSeedWordView (×12 or ×24)
    │                       → EnterBenefactorKey → EnterBeneficiaryKey
    │                       → ConfirmEncrypt → EncryptingView → ShowEncryptedQRView
    └── Decrypt: ScanEncryptedQR → EnterBenefactorKey → EnterBeneficiaryKey
                 → DecryptingView → ShowDecryptedSeedView → ShowSeedWordsView

Secret handling
---------------
The seed phrase and both keys are NOT passed through each View's ``view_args``.
view_args are copied into the controller back-stack and would keep a plaintext
copy of every secret around for the whole flow. Instead all secrets live in a
single ``_LegacySession`` held on the controller (see ``_session``), the same
way SeedSigner keeps in-progress secrets on the controller rather than in
navigation state. The session is cleared at every flow boundary (menu entry,
successful completion, and after the seed is handed off to SeedSigner storage),
and the controller's home-wipe also drops it on a power/home exit (see
``patch_controller.py``). view_args carry only non-secret routing values
(word counts, page indices).
"""

import gc
import time
import threading

from seedsigner.views.view import View, Destination, BackStackView
from seedsigner.gui.screens.screen import (
    ButtonListScreen,
    ButtonOption,
    QRDisplayScreen,
    WarningScreen,
    LargeIconStatusScreen,
    RET_CODE__BACK_BUTTON,
)
from seedsigner.gui.screens.scan_screens import ScanScreen
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.settings import SettingsConstants
from seedsigner.gui.components import FontAwesomeIconConstants
from seedsigner.helpers.legacy_encryption import (
    encrypt_seed_phrase,
    decrypt_seed_phrase,
    validate_seed_phrase,
    seed_phrase_error,
    encrypted_to_qr_data,
    qr_data_to_encrypted,
)
from seedsigner.models.encode_qr import GenericStaticQrEncoder


class _LegacySession:
    """
    Single home for the secrets of one encrypt/decrypt flow.

    Lives on the controller (``controller.legacy_session``) so there is exactly
    one copy of each secret, instead of a copy in every View's view_args / the
    back-stack. ``clear()`` drops the references and forces a collection — the
    most a CPython program can do, since ``str`` is immutable and cannot be
    overwritten in place (the same limitation SeedSigner's own seed handling
    has).
    """

    __slots__ = ("seed_phrase", "benefactor_key", "beneficiary_key",
                 "encrypted_data", "mode")

    def __init__(self):
        self.clear()

    def clear(self):
        self.seed_phrase = None
        self.benefactor_key = None
        self.beneficiary_key = None
        self.encrypted_data = None
        self.mode = None
        gc.collect()


def _session(view) -> "_LegacySession":
    """Return the per-flow secret store on the controller, creating it lazily."""
    session = getattr(view.controller, "legacy_session", None)
    if session is None:
        session = _LegacySession()
        view.controller.legacy_session = session
    return session


def _sync_loading_frame(text: str) -> None:
    """Push one loading frame to the display synchronously, bypassing any active screen thread.

    PBKDF2 pins the Pi Zero's single core, so the normal LoadingScreenThread
    (which animates from a background thread) starves and the device deadlocks.
    Instead the encrypt/decrypt views run PBKDF2 in a worker thread and call
    this from the main thread to paint a static progress frame between waits.
    """
    try:
        from PIL import Image, ImageDraw
        from seedsigner.gui.renderer import Renderer
        from seedsigner.gui.components import GUIConstants, Fonts
        r = Renderer.get_instance()
        img = Image.new("RGBA", (r.canvas_width, r.canvas_height), "black")
        draw = ImageDraw.Draw(img)
        font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_body_font_size())
        draw.text(
            (r.canvas_width // 2, r.canvas_height // 2),
            text,
            fill="white",
            font=font,
            anchor="mm",
        )
        with r.lock:
            r.show_image(img, show_direct=True)
    except Exception:
        pass  # Never block the encrypt/decrypt flow


class _RawQRDecoder(DecodeQR):
    """
    Accepts any QR as raw text — used for scanning the Legacy encrypted payload.

    DecodeQR classifies our base64 blob as INVALID so we bypass its type-detection
    and call pyzbar directly.

    Pi Zero freeze fix — run pyzbar in a daemon thread:
      A CPU-bound C extension (libzbar) cannot be interrupted from the main
      thread because Python only processes signals between bytecodes and libzbar
      never returns to Python while it is stuck. The daemon-thread approach keeps
      the main thread free at all times: we launch a decode thread and return
      FALSE immediately; on the next frame we check whether the thread finished.
      If libzbar ever wedges, the daemon thread is abandoned (it dies with the
      process) but the UI stays alive and the user can press back.

    One thread is allowed at a time — if a thread is still running when the next
    eligible frame arrives we skip that frame rather than pile up threads.
    """

    def __init__(self):
        super().__init__(wordlist_language_code="en")
        self._raw_text = None
        self._frame_count = 0
        self._worker = None          # active daemon decode thread
        self._worker_result = None   # written by thread, read by main thread

    def add_image(self, image):
        self._frame_count += 1

        # Check whether the previous worker finished
        if self._worker is not None:
            if not self._worker.is_alive():
                result = self._worker_result
                self._worker = None
                self._worker_result = None
                if result is not None:
                    self._raw_text = result
                    self.complete = True
                    return DecodeQRStatus.COMPLETE
                # Thread finished but found nothing — fall through to maybe try again
            else:
                # Still running — don't block, skip this frame
                return DecodeQRStatus.FALSE

        # Rate-limit: only launch a new decode every 3rd frame
        if self._frame_count % 3 != 0:
            return DecodeQRStatus.FALSE

        if image is None:
            return DecodeQRStatus.FALSE

        # Full-resolution green channel. Encrypted QRs are denser than seed QRs
        # (Version 10+ vs Version 4-5), so the 2x downsample we used for seed QRs
        # leaves only ~4 pixels per module on a phone screen — right at pyzbar's
        # floor. Full res doubles that margin.
        full_green = image[:, :, 1].copy()

        def _decode():
            try:
                # Attempt 1: full-res green channel
                data = DecodeQR.extract_qr_data(full_green, is_binary=True)
                if data is not None:
                    try:
                        self._worker_result = data.decode("utf-8").strip()
                    except Exception:
                        self._worker_result = data.decode("latin-1").strip()
                    return

                # Attempt 2: contrast-stretch the same image.
                # Phone screens expose the camera to a bright white field; auto-exposure
                # may compress the dynamic range so QR modules land in a narrow grey band
                # rather than full black-to-white. Stretching to the full 0-255 range
                # gives pyzbar sharper module edges.
                mn = int(full_green.min())
                mx = int(full_green.max())
                if mx > mn:
                    stretched = ((full_green.astype('float32') - mn) * (255.0 / (mx - mn))).astype('uint8')
                    data = DecodeQR.extract_qr_data(stretched, is_binary=True)
                    if data is not None:
                        try:
                            self._worker_result = data.decode("utf-8").strip()
                        except Exception:
                            self._worker_result = data.decode("latin-1").strip()
            except Exception:
                pass

        self._worker = threading.Thread(target=_decode, daemon=True)
        self._worker.start()
        return DecodeQRStatus.FALSE

    def get_percent_complete(self, weight_mixed_frames: bool = False) -> int:
        return 100 if self.complete else 0

    def get_raw_text(self):
        return self._raw_text


class _ThreadedDecodeQR(DecodeQR):
    """
    Seed QR decoder that runs pyzbar in a daemon thread — same pattern as
    _RawQRDecoder.

    Why a thread rather than the main loop:
    - pyzbar (ctypes call into libzbar) may hold the GIL for 200ms–2s on a
      complex/blurry frame; in the main thread that freezes the display.
      Moving it to a daemon thread gives the OS scheduler a chance to run
      LivePreviewThread between frames.
    - Only extract_qr_data() runs in the thread (pure pyzbar, no state
      mutation). add_data() is called back in the main thread once the thread
      completes — no concurrent writes to DecodeQR's internal state.
    - Green channel only (2x spatial downsample → 240×240×1): 12x less pixel
      data than the original 480×480 RGB, matching _RawQRDecoder. libzbar is
      just as effective on grayscale for QR codes.

    One thread at a time; every 3rd frame.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._frame_count = 0
        self._worker = None
        self._worker_result = None  # raw bytes from pyzbar, written by thread

    def add_image(self, image):
        self._frame_count += 1

        # Check whether the previous worker finished
        if self._worker is not None:
            if not self._worker.is_alive():
                raw = self._worker_result
                self._worker = None
                self._worker_result = None
                if raw is not None:
                    # add_data() mutates decoder state — run in main thread
                    return self.add_data(raw)
                # Thread finished but found nothing — fall through to retry
            else:
                # Still running — skip this frame
                return DecodeQRStatus.FALSE

        if self._frame_count % 3 != 0:
            return DecodeQRStatus.FALSE

        if image is None:
            return DecodeQRStatus.FALSE

        # Green channel only: 12x less data than 480×480 RGB, same as _RawQRDecoder
        small = image[::2, ::2, 1].copy()

        def _decode():
            try:
                self._worker_result = DecodeQR.extract_qr_data(small, is_binary=True)
            except Exception:
                pass

        self._worker = threading.Thread(target=_decode, daemon=True)
        self._worker.start()
        return DecodeQRStatus.FALSE


def _make_key_entry_screen(label: str):
    """
    Returns a SeedAddPassphraseScreen subclass with a custom title.
    Returns the class (not an instance) so run_screen() instantiates it.
    """
    from dataclasses import dataclass
    from seedsigner.gui.screens.seed_screens import SeedAddPassphraseScreen
    from seedsigner.gui.components import TopNav, GUIConstants

    @dataclass
    class KeyEntryScreen(SeedAddPassphraseScreen):
        def __post_init__(self):
            super().__post_init__()
            old = self.top_nav
            self.top_nav = TopNav(
                text=label,
                width=self.canvas_width,
                height=GUIConstants.TOP_NAV_HEIGHT,
                show_back_button=old.show_back_button,
                show_power_button=old.show_power_button,
            )
            idx = self.components.index(old)
            self.components[idx] = self.top_nav

    return KeyEntryScreen


# ===================================================================
# Main menu
# ===================================================================

class LegacyMainMenuView(View):
    ENCRYPT = ButtonOption("Encrypt Seed Phrase", FontAwesomeIconConstants.LOCK)
    DECRYPT = ButtonOption("Decrypt Seed Phrase", FontAwesomeIconConstants.UNLOCK)

    def run(self) -> Destination:
        # Entering the menu is a flow boundary: wipe any secrets left over from
        # an abandoned (backed-out) flow.
        _session(self).clear()

        button_data = [self.ENCRYPT, self.DECRYPT]

        selected = self.run_screen(
            ButtonListScreen,
            title="Legacy Encryption",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected] == self.ENCRYPT:
            return Destination(LegacyEncryptInputMethodView)

        if button_data[selected] == self.DECRYPT:
            return Destination(LegacyDecryptScanQRView)


# ===================================================================
# ENCRYPT input method selection
# ===================================================================

class LegacyEncryptInputMethodView(View):
    SCAN_QR = ButtonOption("Scan Seed QR")
    ENTER_MANUALLY = ButtonOption("Enter Manually")

    def run(self) -> Destination:
        button_data = [self.SCAN_QR, self.ENTER_MANUALLY]

        selected = self.run_screen(
            ButtonListScreen,
            title="Encrypt Seed",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected] == self.SCAN_QR:
            return Destination(LegacyEncryptScanSeedView)

        return Destination(LegacyManualSeedWordCountView)


class LegacyManualSeedWordCountView(View):
    TWELVE = ButtonOption("12 words")
    TWENTY_FOUR = ButtonOption("24 words")

    def run(self) -> Destination:
        button_data = [self.TWELVE, self.TWENTY_FOUR]

        selected = self.run_screen(
            ButtonListScreen,
            title="Seed Length",
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        num_words = 12 if button_data[selected] == self.TWELVE else 24
        self.controller.storage.init_pending_mnemonic(num_words=num_words)
        return Destination(
            LegacyEnterSeedWordView,
            view_args={"cur_word_index": 0, "num_words": num_words},
        )


class LegacyEnterSeedWordView(View):
    OK = ButtonOption("OK")

    def __init__(self, cur_word_index: int = 0, num_words: int = 12):
        super().__init__()
        self.cur_word_index = cur_word_index
        self.num_words = num_words
        self.cur_word = self.controller.storage.get_pending_mnemonic_word(cur_word_index)

    def run(self) -> Destination:
        from seedsigner.gui.screens import seed_screens
        from seedsigner.models.seed import Seed

        wordlist_lang = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        wordlist = Seed.get_wordlist(wordlist_language_code=wordlist_lang)

        ret = self.run_screen(
            seed_screens.SeedMnemonicEntryScreen,
            title=f"Word {self.cur_word_index + 1} of {self.num_words}",
            initial_letters=list(self.cur_word) if self.cur_word else ["a"],
            wordlist=wordlist,
        )

        if ret == RET_CODE__BACK_BUTTON:
            if self.cur_word_index == 0:
                self.controller.storage.discard_pending_mnemonic()
            return Destination(BackStackView)

        self.controller.storage.update_pending_mnemonic(ret, self.cur_word_index)

        if self.cur_word_index < self.num_words - 1:
            return Destination(
                LegacyEnterSeedWordView,
                view_args={"cur_word_index": self.cur_word_index + 1, "num_words": self.num_words},
            )

        # All words entered — collect, validate, and discard from storage
        words = [
            self.controller.storage.get_pending_mnemonic_word(i)
            for i in range(self.num_words)
        ]
        seed_phrase = " ".join(words)
        self.controller.storage.discard_pending_mnemonic()

        err = seed_phrase_error(seed_phrase)
        if err is not None:
            self.run_screen(
                WarningScreen,
                title="Invalid Seed",
                status_headline="Invalid Seed",
                text=err + " Check all words carefully and try again.",
                button_data=[self.OK],
            )
            return Destination(LegacyManualSeedWordCountView)

        session = _session(self)
        session.seed_phrase = seed_phrase
        session.mode = "encrypt"
        return Destination(LegacyEnterBenefactorKeyView)


# ===================================================================
# ENCRYPT flow
# ===================================================================

class LegacyEncryptScanSeedView(View):
    OK = ButtonOption("OK")

    def run(self) -> Destination:
        from seedsigner.hardware.camera import Camera
        Camera.get_instance().stop_for_pbkdf2()  # kill any stale parked stream before fresh open
        wordlist_lang = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        decoder = _ThreadedDecodeQR(wordlist_language_code=wordlist_lang)

        self.run_screen(
            ScanScreen,
            instructions_text="Scan your SeedQR",
            decoder=decoder,
        )

        if not decoder.is_complete:
            return Destination(BackStackView)

        if not decoder.is_seed:
            self.run_screen(
                WarningScreen,
                title="Wrong QR Type",
                status_headline="Not a SeedQR",
                text="Scan the QR that represents your seed phrase — not an encrypted Legacy QR.",
                button_data=[self.OK],
            )
            return Destination(BackStackView)

        seed_phrase = " ".join(decoder.get_seed_phrase())

        if not validate_seed_phrase(seed_phrase):
            self.run_screen(
                WarningScreen,
                title="Invalid Seed",
                status_headline="Error",
                text="The scanned QR does not contain a valid 12 or 24-word BIP-39 seed phrase.",
                button_data=[self.OK],
            )
            return Destination(BackStackView)

        session = _session(self)
        session.seed_phrase = seed_phrase
        session.mode = "encrypt"
        return Destination(LegacyEnterBenefactorKeyView)


class LegacyEnterBenefactorKeyView(View):
    def run(self) -> Destination:
        ret = self.run_screen(_make_key_entry_screen("Benefactor Key"))

        if ret == RET_CODE__BACK_BUTTON or (isinstance(ret, dict) and ret.get("is_back_button")):
            return Destination(BackStackView)

        key = ret["passphrase"] if isinstance(ret, dict) else ret

        _session(self).benefactor_key = key
        return Destination(LegacyEnterBeneficiaryKeyView)


class LegacyEnterBeneficiaryKeyView(View):
    def run(self) -> Destination:
        ret = self.run_screen(_make_key_entry_screen("Beneficiary Key"))

        if ret == RET_CODE__BACK_BUTTON or (isinstance(ret, dict) and ret.get("is_back_button")):
            return Destination(BackStackView)

        key = ret["passphrase"] if isinstance(ret, dict) else ret

        session = _session(self)
        session.beneficiary_key = key

        if session.mode == "encrypt":
            return Destination(LegacyConfirmEncryptView)
        else:
            return Destination(LegacyDecryptingView)


class LegacyConfirmEncryptView(View):
    CANCEL = ButtonOption("Cancel")

    def run(self) -> Destination:
        session = _session(self)
        word_count = len(session.seed_phrase.split())
        confirm = ButtonOption(f"Encrypt {word_count}-word seed")
        button_data = [confirm, self.CANCEL]

        selected = self.run_screen(
            ButtonListScreen,
            title="Confirm Encrypt",
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON or button_data[selected] == self.CANCEL:
            return Destination(BackStackView)

        return Destination(LegacyEncryptingView)


class LegacyEncryptingView(View):
    OK = ButtonOption("OK")

    def run(self) -> Destination:
        from seedsigner.hardware.camera import Camera

        session = _session(self)

        _sync_loading_frame("Encrypting...  (15-30 sec)")
        Camera.get_instance().stop_for_pbkdf2()  # fully kill camera DMA before PBKDF2

        # PBKDF2 runs in a background thread; main thread does 1fps display updates.
        result_box = [None]
        error_box = [None]
        done = threading.Event()

        def _do_encrypt():
            try:
                result_box[0] = encrypt_seed_phrase(
                    session.seed_phrase,
                    session.benefactor_key,
                    session.beneficiary_key,
                )
            except Exception as e:
                error_box[0] = e
            finally:
                done.set()

        threading.Thread(target=_do_encrypt, daemon=True).start()

        elapsed = 0
        while not done.wait(timeout=1.0):
            elapsed += 1
            _sync_loading_frame(f"Encrypting...  {elapsed}s")

        if error_box[0] is not None:
            self.run_screen(
                WarningScreen,
                title="Encryption Failed",
                status_headline="Error",
                text=str(error_box[0]),
                button_data=[self.OK],
            )
            # Keep the session so the user can go back and retry with the same input.
            return Destination(BackStackView)

        # Encryption succeeded: the plaintext seed and both keys are no longer
        # needed. Drop them now rather than waiting for the terminal screen.
        session.encrypted_data = result_box[0]
        session.seed_phrase = None
        session.benefactor_key = None
        session.beneficiary_key = None
        gc.collect()

        return Destination(LegacyShowEncryptedQRView)


class LegacyShowEncryptedQRView(View):
    READY = ButtonOption("Show QR Code")
    SAVED = ButtonOption("I've saved it")

    def run(self) -> Destination:
        session = _session(self)
        qr_data = encrypted_to_qr_data(session.encrypted_data)
        qr_encoder = GenericStaticQrEncoder(data=qr_data)

        # Warn before showing QR so user has camera ready
        self.run_screen(
            LargeIconStatusScreen,
            title="Get Camera Ready",
            status_headline="Next screen: QR code",
            text="Get ready to photograph the encrypted QR. You cannot recover your seed without it and BOTH keys.",
            button_data=[self.READY],
        )

        # Loop: back from confirmation returns to QR so they can re-photograph
        while True:
            self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
            ret = self.run_screen(
                LargeIconStatusScreen,
                title="Saved?",
                status_headline="Got the photo?",
                text="If you need another look, press back to return to the QR.",
                button_data=[self.SAVED],
            )
            if ret != RET_CODE__BACK_BUTTON:
                break

        session.clear()
        return Destination(LegacyMainMenuView, clear_history=True)


# ===================================================================
# DECRYPT flow
# ===================================================================

class LegacyDecryptScanQRView(View):
    OK = ButtonOption("OK")

    def run(self) -> Destination:
        from seedsigner.hardware.camera import Camera
        Camera.get_instance().stop_for_pbkdf2()  # kill any stale parked stream before fresh open
        decoder = _RawQRDecoder()

        # Use default resolution (480×480) and framerate (6) — the same settings
        # as every other ScanScreen in SeedSigner. PiVideoStream.stop() is a
        # busy-wait spin that can stall indefinitely on Pi Zero at non-standard
        # resolutions. _RawQRDecoder's grayscale conversion + 3x frame skipping
        # keep ZBar fast enough without needing to change the camera settings.
        try:
            self.run_screen(
                ScanScreen,
                instructions_text="Scan Legacy encrypted QR",
                decoder=decoder,
            )
        except Exception:
            # start_video_stream_mode() raises RuntimeError if the camera
            # produces no frames within 5 s (MMAL stuck on second open).
            self.run_screen(
                WarningScreen,
                title="Camera Error",
                status_headline="Please Restart",
                text="The camera failed to start. Power the device off and back on to reset it.",
                button_data=[self.OK],
            )
            return Destination(LegacyMainMenuView, clear_history=True)

        if not decoder.complete:
            return Destination(BackStackView)

        raw_text = decoder.get_raw_text()

        if not raw_text:
            self.run_screen(
                WarningScreen,
                title="Scan Failed",
                status_headline="Try Again",
                text="Could not read the QR code. Make sure it is well-lit and fills the frame.",
                button_data=[self.OK],
            )
            return Destination(BackStackView)

        encrypted_data = qr_data_to_encrypted(raw_text)

        if not encrypted_data:
            self.run_screen(
                WarningScreen,
                title="Wrong QR",
                status_headline="Not a Legacy QR",
                text="This doesn't look like a Legacy Encryption QR. Scan the encrypted QR, not the original SeedQR.",
                button_data=[self.OK],
            )
            return Destination(BackStackView)

        session = _session(self)
        session.encrypted_data = encrypted_data
        session.mode = "decrypt"
        return Destination(LegacyEnterBenefactorKeyView)


class LegacyDecryptingView(View):
    OK = ButtonOption("OK")

    def run(self) -> Destination:
        from seedsigner.hardware.camera import Camera

        session = _session(self)

        _sync_loading_frame("Decrypting...  (15-30 sec)")
        Camera.get_instance().stop_for_pbkdf2()  # fully kill camera DMA before PBKDF2

        result_box = [None]
        error_box = [None]
        done = threading.Event()

        def _do_decrypt():
            try:
                result_box[0] = decrypt_seed_phrase(
                    session.encrypted_data,
                    session.benefactor_key,
                    session.beneficiary_key,
                )
            except Exception as e:
                error_box[0] = e
            finally:
                done.set()

        threading.Thread(target=_do_decrypt, daemon=True).start()

        elapsed = 0
        while not done.wait(timeout=1.0):
            elapsed += 1
            _sync_loading_frame(f"Decrypting...  {elapsed}s")

        if error_box[0] is not None:
            msg = str(error_box[0])
            if any(k in msg.lower() for k in ("tag", "authentication", "invalid")):
                msg = "Decryption failed. Check that both keys are correct — spelling, capitalization, and spaces all matter."
            self.run_screen(
                WarningScreen,
                title="Decryption Failed",
                status_headline="Wrong Keys?",
                text=msg,
                button_data=[self.OK],
            )
            # Keep the session so the user can go back and retry the keys.
            return Destination(BackStackView)

        if not validate_seed_phrase(result_box[0]):
            self.run_screen(
                WarningScreen,
                title="Bad Result",
                status_headline="Check Your Keys",
                text="Decryption ran but the result is not a valid BIP-39 seed phrase. Double-check both keys and try again.",
                button_data=[self.OK],
            )
            return Destination(BackStackView)

        # Decryption succeeded: keys and ciphertext are no longer needed.
        session.seed_phrase = result_box[0]
        session.benefactor_key = None
        session.beneficiary_key = None
        session.encrypted_data = None
        gc.collect()

        return Destination(LegacyShowDecryptedSeedView)


class LegacyShowDecryptedSeedView(View):
    LOAD       = ButtonOption("Load into SeedSigner")
    SHOW_WORDS = ButtonOption("Read Seed Words")
    EXPORT_QR  = ButtonOption("Export as SeedQR")
    DONE       = ButtonOption("Done  (clears memory)")

    def run(self) -> Destination:
        session = _session(self)
        seed_phrase = session.seed_phrase
        word_count = len(seed_phrase.split())
        button_data = [self.LOAD, self.SHOW_WORDS, self.EXPORT_QR, self.DONE]

        selected = self.run_screen(
            ButtonListScreen,
            title=f"Decrypted  ({word_count} words)",
            button_data=button_data,
            is_button_text_centered=True,
            show_back_button=False,
        )

        if selected == RET_CODE__BACK_BUTTON:
            # Physical back button still fires even with show_back_button=False.
            # Loop back to the same screen — user must press Done to exit.
            return Destination(LegacyShowDecryptedSeedView)

        if button_data[selected] == self.LOAD:
            from seedsigner.models.seed import Seed
            from seedsigner.views.seed_views import SeedFinalizeView
            words = seed_phrase.split()
            self.controller.storage.set_pending_seed(Seed(mnemonic=words))
            # Seed is now owned by SeedSigner storage — drop our copy.
            session.clear()
            return Destination(SeedFinalizeView, clear_history=True)

        if button_data[selected] == self.SHOW_WORDS:
            return Destination(
                LegacyShowSeedWordsView,
                view_args={"page_index": 0},
            )

        if button_data[selected] == self.EXPORT_QR:
            from seedsigner.models.encode_qr import SeedQrEncoder
            qr_encoder = SeedQrEncoder(mnemonic=seed_phrase.split())
            self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
            return Destination(LegacyShowDecryptedSeedView)

        # DONE
        session.clear()
        return Destination(LegacyMainMenuView, clear_history=True)


class LegacyShowSeedWordsView(View):
    NEXT = ButtonOption("Next")
    DONE = ButtonOption("Done")

    def __init__(self, page_index: int = 0):
        super().__init__()
        self.page_index = page_index

    def run(self) -> Destination:
        from seedsigner.gui.screens.seed_screens import SeedWordsScreen

        words = _session(self).seed_phrase.split()
        words_per_page = 4
        num_pages = (len(words) + words_per_page - 1) // words_per_page
        page_words = words[self.page_index * words_per_page:(self.page_index + 1) * words_per_page]
        is_last_page = self.page_index >= num_pages - 1
        button_data = [self.DONE if is_last_page else self.NEXT]

        selected = self.run_screen(
            SeedWordsScreen,
            words=page_words,
            page_index=self.page_index,
            num_pages=num_pages,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected] == self.NEXT:
            return Destination(
                LegacyShowSeedWordsView,
                view_args={"page_index": self.page_index + 1},
            )

        return Destination(LegacyShowDecryptedSeedView)
