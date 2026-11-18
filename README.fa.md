# signed-updater

به‌روزرسانی امن برای **اپ‌های دسکتاپ Flutter / Dart** روی ویندوز، لینوکس و مک.
سرور به‌روزرسانی **غیرقابل‌اعتماد** فرض می‌شود: هر نسخه با یک مدخل مانیفست
امضاشده با **Ed25519** توصیف می‌شود و کلاینت آن را با **کلید عمومی تعبیه‌شده در
خود اپ** راستی‌آزمایی می‌کند.

[English](README.md)

- `updsign` (Go): ساخت کلید، امضای فایل، مدیریت مانیفست و راستی‌آزمایی.
- `signed_updater` (Dart): دریافت مانیفست، راستی‌آزمایی، دانلود، هش مجدد و نصب.
- هر دو سمت یک قالب پیام امضاشده دارند و این را فیکسچرهایی ثابت می‌کنند که ابزار
  Go می‌سازد و تست‌های Dart راستی‌آزمایی می‌کنند.

## چرا فقط «sha256 داخل مانیفست» کافی نیست؟

اگر مانیفست و نصب‌کننده روی یک سرور باشند، کسی که سرور را بگیرد هر دو را عوض
می‌کند. امضای آفلاین با کلیدی که هیچ‌وقت روی سرور نیست این راه را می‌بندد. امضای
فقط‌هش هم اجازه می‌دهد فایل قدیمی با برچسب نسخه‌ی جدید عرضه شود؛ پس اینجا کل
چندتایی امضا می‌شود:

```
<context>\n
version=<version>\n
build=<build>\n
platform=<platform>\n
sha256=<hex>\n
size=<bytes>\n
notes_sha256=<hex>\n
```

`<context>` رشته‌ی جداسازی دامنه است که برای هر محصول خودتان انتخاب می‌کنید
(مثلاً `myapp-update-v1`)؛ امضای یک اپ برای اپ دیگر بی‌معناست.

## شروع سریع

### ۱. ناشر (Go 1.23 به بالا)

```sh
go install github.com/soh1eil/signed-updater/cmd/updsign@latest

updsign keygen -out release.key         # کلید عمومی (۶۴ نویسه‌ی hex) را چاپ می‌کند؛ مجوز فایل 0600
export UPDSIGN_CONTEXT=myapp-update-v1  # یا -context

updsign manifest add \
  -manifest updates/windows.json -key release.key \
  -file dist/MyApp-1.4.0-setup.exe -url files/MyApp-1.4.0-setup.exe \
  -version 1.4.0 -build 42 -platform windows -notes "رفع اشکال"

updsign verify -pub <PUBKEY> -manifest updates/windows.json -file dist/MyApp-1.4.0-setup.exe
```

`updsign` فایل کلیدی را که برای گروه یا دیگران قابل‌خواندن باشد نمی‌پذیرد، کلید
موجود را بازنویسی نمی‌کند و مانیفست را اتمیک می‌نویسد. `manifest add` نسخه‌ای را
که از جدیدترین نسخه‌ی همان پلتفرم جدیدتر نیست منتشر نمی‌کند، مگر با `-allow-older`.

دستورها: `keygen`، `pub`، `sign`، `verify`، `manifest add | rm | list`.

آدرس `url` باید یک مسیر **نسبی** ساده باشد (بدون scheme، بدون `//host`، بدون
`..`) و نسبت به آدرس مانیفست حل می‌شود؛ پس فایل هرگز از مبدأ مانیفست بیرون نمی‌رود.
فایل‌ها و مانیفست را به‌صورت ایستا آپلود کنید؛ سمت سرور چیزی لازم نیست.

### ۲. اپ (Dart / Flutter دسکتاپ)

```dart
final updater = SignedUpdater(
  config: UpdaterConfig(
    manifestUrl: Uri.parse('https://example.com/updates/windows.json'),
    publicKeys: ['<PUBKEY>'],          // داخل اپ تعبیه می‌شود، هرگز از شبکه نمی‌آید
    context: 'myapp-update-v1',        // باید با context ابزار updsign یکی باشد
    platform: 'windows',
    currentVersion: '1.3.0',
    currentBuild: 41,
  ),
  stateStore: FileStateStore('$appSupportDir/update-state.json'), // حافظه‌ی ضدبازگشت
  installer: WindowsInstaller(arguments: ['/VERYSILENT', '/NORESTART']),
);

final r = await updater.check();
if (r is UpdateAvailable) {
  final verified = await updater.download(r.release, Directory('$cacheDir/updates'));
  await updater.install(verified);   // بعد از آن از اپ خارج شوید
}
```

کلاینت این‌ها را اجبار می‌کند: فقط کلید(های) پین‌شده؛ مانیفست فقط `https`؛
گرامر سخت‌گیرانه‌ی مانیفست با سقف ۱ مگابایت؛ تأیید امضا پیش از هر دانلود؛ فقط
آدرس نسبی و تغییر مسیر هم‌مبدأ (حداکثر ۳)؛ سقف حجم هنگام دانلود و هش تدریجی؛
هش مجدد از روی دیسک بعد از نوشتن و درست پیش از نصب؛ نسخه باید از اپ در حال اجرا
جدیدتر و از «بالاترین نسخه‌ی دیده‌شده» قدیمی‌تر نباشد.

### نصب‌کننده‌ها

`Installer` یک اینترفیس تک‌متدی است. همراه بسته: `WindowsInstaller`،
`LinuxInstaller` (جایگزینی اتمیک AppImage با نگه‌داشتن `.old`)،
`MacOsInstaller` و `CommandInstaller` (مسیر فایل یک آرگومان است، نه رشته‌ی شل).

## اسناد امنیتی

- [مدل تهدید](docs/threat-model.md): چه چیزی محافظت می‌شود و چه چیزی نه (سرور
  آلوده، MITM، بازگشت به نسخه‌ی قدیم، توقف به‌روزرسانی، گم‌شدن کلید).
- [چرخش کلید](docs/key-rotation.md): کلید جدید در نسخه‌ای می‌آید که با کلید قدیم
  امضا شده است.

## توسعه

```sh
go vet ./... && go test -race ./...
go test ./manifest -run xxx -fuzz FuzzParse -fuzztime 30s
go test ./manifest -run Interop -update

cd dart/signed_updater && dart pub get && dart analyze && dart test
```

## محدودیت‌ها

به‌روزرسانی دلتا، انتشار مرحله‌ای، ابطال درون‌باندی، انقضای مانیفست و پسوند
پیش‌انتشار در نسخه‌ی ۱ وجود ندارد. بررسی مجوز فایل کلید روی ویندوز انجام نمی‌شود
(از ACL استفاده کنید).

## مجوز

MIT، فایل [LICENSE](LICENSE).
