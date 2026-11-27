# LAN Transfer Core (Rust)

**الحالة: نواة أولية قابلة للمراجعة والاختبار — وليست إصدارًا نهائيًا للمستخدمين.**

هذا المشروع هو أول تنفيذ عملي لنواة نقل ملفات محلية بين جهازين على نفس شبكة LAN. الاسم مؤقت إلى أن يتم اختيار الاسم النهائي.

## ما الذي يحتويه هذا التسليم؟

- مصدر Rust مثبت على الإصدار المستقر `1.100.0` في `rust-toolchain.toml`، مع تثبيت إصدارات الاعتماديات المباشرة في `Cargo.toml`.
- إرسال واستقبال ملف واحد في الجلسة.
- نقل عبر TCP داخل الشبكة المحلية، بدون Cloud أو Relay أو اعتماد على الإنترنت.
- اقتران باستخدام سر عشوائي مؤقت بطول 256 بت، يظهر على جهاز الاستقبال ويُدخل على جهاز الإرسال دون إظهاره أثناء الكتابة على الطرفية.
- قناة مشفرة باستخدام مكتبة `snow` وبروتوكول Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s`؛ ولا نعتمد على TLS هنا، بل على Noise مع مفتاح جلسة مشترك.
- تأكيد امتلاك سر الاقتران عبر أول رسالة مشفرة قبل قبول الجلسة.
- دعم امتدادات ZIP والصور والفيديو المحددة في `src/transfer.rs`.
- نقل متدفق بكتل 32 KiB بدل تحميل الملف كاملًا في الذاكرة.
- حساب SHA-256 ومقارنته قبل تثبيت الملف النهائي.
- رفض مسارات الملفات وأسماء Windows المحجوزة.
- استقبال إلى ملف مؤقت، ثم تثبيت بدون الكتابة فوق ملف موجود.
- موافقة صريحة من مستخدم جهاز الاستقبال قبل كتابة الملف.
- لا توجد خدمة Windows مخفية أو تشغيل تلقائي أو طلب صلاحيات Administrator.

## ما الذي لم يكتمل بعد؟

هذه ليست النسخة الكاملة التي وصفتها في الخطة. العناصر التالية غير موجودة في هذا التسليم:

1. واجهة Windows Native الرسومية.
2. اكتشاف الأجهزة تلقائيًا عبر mDNS؛ الاتصال حاليًا بعنوان IP/hostname يدويًا.
3. فحص Antivirus عند الطلب أو تكامل رسمي مع Microsoft Defender.
4. استكمال النقل بعد انقطاع الاتصال، وإرسال عدة ملفات في جلسة واحدة.
5. Adaptive Resource Engine ومراقبة CPU/RAM وضبط الأداء تلقائيًا.
6. مثبت Windows، وتوقيع Code Signing، وتحديثات آمنة.
7. اختبار فعلي على Windows 8/8.1 أو أي جهاز Windows آخر.
8. مراجعة أمنية مستقلة للبروتوكول والتنفيذ.

لا تستخدمه لنقل ملفات حساسة أو على شبكة غير موثوقة قبل مراجعة الكود واختباره. التشفير لا يساوي فحصًا ضد البرمجيات الخبيثة، وامتداد الملف ليس إثباتًا لمحتواه.

## المتطلبات

- Rust `1.100.0` (مثبت بواسطة rustup في هذا المستودع).
- Cargo.
- اتصال إنترنت أول مرة لتنزيل الاعتماديات.
- جهازان على نفس الشبكة المحلية.

التثبيت الرسمي لـ Rust: https://www.rust-lang.org/tools/install

## البناء والاختبار

يحتوي هذا التسليم على `Cargo.lock` لتثبيت الاعتماديات الانتقالية. استخدم `--locked` في البناء والاختبارات حتى لا تتغير شجرة الاعتماديات بصمت، وراجع تحديثات الاعتماديات أمنيًا قبل دمجها.

```powershell
rustup show
cargo +1.100.0 fmt --check
cargo +1.100.0 clippy --locked --all-targets -- -D warnings
cargo +1.100.0 test --locked --all-targets
cargo +1.100.0 build --locked --release
```

## تجربة النقل

### على الجهاز المستقبِل

أنشئ مجلد استقبال أولًا، ثم شغّل:

```powershell
cargo run --release -- receive 0.0.0.0:45123 "$env:USERPROFILE\Downloads\LAN-Received"
```

سيظهر كود اقتران مؤقت. احتفظ به ولا تشاركه إلا مع الجهاز المقصود. الجلسة تنتهي بعد خمس دقائق أو بعد أول اتصال موثّق.

اعرف عنوان IPv4 المحلي للجهاز باستخدام:

```powershell
ipconfig
```

### على الجهاز المُرسِل

```powershell
cargo run --release -- send 192.168.1.20:45123 "$env:USERPROFILE\Pictures\photo.jpg"
```

استبدل العنوان والمسار بالقيم الفعلية. سيطلب الجهاز المُرسل كود الاقتران تفاعليًا بدل وضعه في معاملات سطر الأوامر، ثم يطلب الجهاز المستقبل موافقة محلية قبل حفظ الملف. إدخال كود الاقتران مخفي في الطرفية ولا يظهر كنص أثناء الكتابة.

> اسمح بالاتصال على الشبكة الخاصة فقط عند مطالبة Windows Firewall بذلك. لا تنشئ قاعدة Firewall عامة أو واسعة يدويًا.

## الملفات المدعومة مبدئيًا

- ZIP: `.zip`
- الصور: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.webp`
- الفيديو: `.mp4`, `.mkv`, `.mov`, `.avi`, `.webm`

التصنيف يعتمد حاليًا على الامتداد، وليس على تحليل كامل لصيغة الملف. لا يتم فك ضغط ZIP أو تشغيل أي ملف تلقائيًا.

## ملاحظات توافق Windows

الأهداف القياسية الحالية لـ Rust MSVC تتطلب Windows 10 أو أحدث. توجد أهداف Tier 3 خاصة بـ Windows 7 مثل `x86_64-win7-windows-msvc`، لكنها تحتاج بناء `std` مخصصًا ولا توفر Rust لها مكتبات جاهزة؛ لذلك مسار Windows 8/8.1 في هذا المستودع **تجريبي وغير معتمد** حتى ننجح في بناء نسخة مخصصة واختبارها على النظام نفسه.

راجع `docs/windows-compatibility.md` قبل محاولة البناء على نظام قديم.

راجع [`docs/security-audit-initial-2026-11-27.md`](docs/security-audit-initial-2026-11-27.md)
للاطلاع على نطاق المراجعة الأولية، والإصلاحات التي ما زالت تحتاج إلى تحقق، والمخاطر المفتوحة.
راجع أيضًا [`docs/validation-status-2026-11-27.md`](docs/validation-status-2026-11-27.md)
لسجل نتائج Windows التي قدمها مالك المشروع وبوابات القبول المتبقية.


## Smart App Control compatibility

The repository includes a signed-release pipeline designed for Windows 11 PCs
with Smart App Control enabled. Read [`docs/smart-app-control.md`](docs/smart-app-control.md)
before building or distributing the application. The supplied Code Integrity
event with policy ID `{0283ac0f-fff1-49ae-ada1-8a933130cad6}` matches the
`VerifiedAndReputableDesktop` Smart App Control enforcement policy.

**Important:** Smart App Control can block unsigned Cargo-generated build
scripts while `cargo check` or `cargo build` is running. Signing the final EXE
does not sign these temporary build tools. On a PC affected by this policy,
use the GitHub-hosted build workflow rather than disabling Smart App Control.
The signed-release workflow intentionally fails closed and will not publish an
unsigned executable. It requires the repository owner to complete a trusted
signing-provider setup first. The regular CI build is unsigned and is only for
build/test validation; do not attempt to run its EXE on a PC where Smart App
Control blocks unsigned applications. A source ZIP is not a signed binary.

The release workflow currently signs the CLI executable only. When the app
adds a GUI, DLLs, helper executables, updater, or installer, each executable
component must be added to the signing configuration and signature checks.

Read-only diagnostic command:

```powershell
.\scripts\Show-SmartAppControlStatus.ps1
```

## الترخيص

Apache-2.0. راجع `LICENSE` و`NOTICE`.
