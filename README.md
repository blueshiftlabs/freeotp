Sites that use Authy don't currently have any sort of support
for generating tokens on Android Wear. This repository adds
a reverse-engineered Authy token code implementation, based on
the algorithm used in Authy for Android 21.0 (in broad terms,
a rather buggy version of the TOTP RFC).

Notes on use:

- You'll need to have the Authy app installed, and you'll need
  to be rooted.

- Open the following file with root in your favorite editor:
  /data/data/com.authy.authy/shared_prefs/com.authy.storage.tokens.authy.xml

- Look for "secretSeed" entries in that file. They should contain 32
  hex digits, one entry for each Authy (non-Authenticator) account
  you have on that device. (It helps a lot to run the contents of the
  file through an HTML entities decoder and a JSON beautifier.)

- Make FreeOTP entries for those accounts as follows:
    - Secret: The "secretSeed" from Authy (it'll enter as upper-case hex)
    - Type: Authy
    - Digits: 7
    - Algorithm: SHA1
    - Interval: 10

- Confirm that codes are being generated properly against your installed
  Authy app. (Note that Authy does some clock-synchronization stuff, so
  there may be some skew in when a given code is generated.)

- Tap the '...' menu on one of your tokens, and tap "Send to Wear" to
  send everything to your Wear device. It will then be able to generate
  tokens, even if it's offline or disconnected from your phone.

Note: this is tested very poorly, and only on my device (Note 2, stock
but heavily modded with Xposed).

Special thanks to:
- The FreeOTP authors
- Hoyt Summers Pittman, for writing the Android Wear support for FreeOTP
- rovo89 and tungstwenty, for creating Xposed Framework, which greatly
  helped in the reverse-engineering effort
- brutall, for creating apktool, which made this project possible

Have fun!

- Justin Paupore (blueshiftlabs)
