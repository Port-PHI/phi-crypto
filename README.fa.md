<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/phi-mark-dark.svg">
  <img src="assets/phi-mark.svg" alt="Phi (φ)" width="170">
</picture>

# phi-crypto — رمزنگاریِ هویتِ فی

[![CI](https://github.com/Port-PHI/phi-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/Port-PHI/phi-crypto/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org/)

[**English**](./README.md) · **فارسی**

شرکت داده هوشمند هومان · [portphi.com](https://portphi.com)

</div>

---

<div dir="rtl">

**رمزنگاریِ حافظِ حریمِ خصوصی در پسِ اثباتِ انسان‌بودن، احرازِ هویت و مدارکِ قابلِ‌راستی‌آزمایی** · *هرگز رمزنگاری را دستی ننویس*

## phi-crypto چیست؟

**phi-crypto** هسته‌ی رمزنگاریِ شبکه‌ی [فی](https://portphi.com) است — همان بلاکچینِ هویتی که به یک
فرد امکان می‌دهد ثابت کند کیست و حقِ ادعای چه چیزی را دارد، **بی‌آنکه داده‌های شخصیِ خامش را فاش
کند.** این کتابخانه موتوری است که این را ممکن می‌کند: اثبات‌های بدون‌افشا، شناسه‌های غیرمتمرکز، و
احرازِ هویتِ مقیدِ دستگاه که یک انسانِ یک‌بار‌احرازشده را به یک هویتِ دیجیتالِ خصوصی، خودمالک و
قابلِ‌راستی‌آزمایی بدل می‌کنند.

یک‌بار در **Rust** نوشته می‌شود و از یک پیاده‌سازیِ واحد به هر مصرف‌کننده‌ی فی سرویس می‌دهد: زنجیره
(Go، از مسیرِ C-ABI)، اپِ موبایل (FFI) و وب (WebAssembly). یک هسته، سه خروجی — چون یک باگِ رمزنگاری
که در چند پیاده‌سازیِ موازی تکرار شود فاجعه است، رمزنگاریِ حساسِ کلِ شبکه دقیقاً در یک جای
قابلِ‌بازبینی زندگی می‌کند.

این کتابخانه **هرگز رمزنگاری را دستی پیاده نمی‌کند.** هر اولیه یک wrapperِ نازک و بازبینی‌شده روی یک
کریتِ بالغ و ممیزی‌شده است (`docknetwork/crypto` و `pairing_crypto` برای BBS+، کریت‌های
`k256`/`p256`ِ RustCrypto برای امضا، arkworks/blst برای BLS12-381). اسنادِ کامل در [`NOTICE`](./NOTICE)
آمده است.

## چه چیزی را توان می‌بخشد؟

phi-crypto بلوک‌های سازنده‌ی لایه‌ی هویتِ فی را فراهم می‌کند:

- **مدارک و افشای انتخابی (`bbs`، `bbs_2023`).** امضاهای افشای انتخابیِ غیرقابلِ‌اتصالِ BBS+ روی
  BLS12-381. دارنده می‌تواند گزاره‌ای را ثابت کند — *«بالای ۱۸»، «ساکنِ شهرِ X»، «یک انسانِ
  احرازشده»* — **بی‌فاش‌سازیِ داده‌ی پشتِ آن**، و دو ارائه از یک مدرک به‌هم قابلِ‌اتصال نیستند. سوئیتِ
  `bbs-2023` با بردارهای رسمیِ تعامل‌پذیریِ IETF/W3C بایت‌به‌بایت مطابقت دارد.

- **هویتِ غیرمتمرکز (`did`).** تولیدِ کلید و امضا روی هر دو منحنی (secp256k1 و secp256r1)، شناسه‌های
  `did:phi:…`، و امضاهای low-Sِ اجباری — ستونِ فقراتِ رمزنگاریِ هویتِ خودمالکِ فی.

- **احرازِ هویتِ مقیدِ دستگاه (`webauthn`).** یک وریفایرِ WebAuthn (P-256) روی
  `authenticatorData ‖ SHA256(clientDataJSON)` که نوع، challenge، origin، هویتِ relying-party،
  User-Presence و low-S را بررسی می‌کند — تا «ورود با فی» با یک passkeyِ واقعی روی دستگاهی واقعی
  پشتیبانی شود.

- **مشارکتِ خصوصی (`voting`، `semaphore`).** اولیه‌های nullifier و شمارشِ آستانه‌ای که یک اثباتِ مدرک
  را به یک کنشِ ناشناسِ یگانه گره می‌زنند — پایه‌ی مشارکتِ یک‌انسان‑یک‑رأی بی‌فاش‌سازیِ هویت.

- **مرزِ C-ABI (`ffi`).** تنها ماژولِ `unsafe`: مرزی بی‌panic و fail-safe که به زنجیره اجازه می‌دهد
  امن از مرزِ FFI به هسته فراخوان بزند. توابعِ راستی‌آزمایی برای معتبر `1` و در غیرِاین‌صورت `0`
  برمی‌گردانند — fail-closed.

## یک هسته، سه خروجی

```
                      ┌─────────────────────────────┐
                      │  phi-crypto (Rust core)      │
                      │  bbs · did · webauthn · vote │
                      └──────────────┬──────────────┘
        ┌──────────────────┬─────────┴──────────┬──────────────────┐
   WASM (wasm.rs)     FFI (flutter_bridge)   C-ABI (ffi.rs + cbindgen)
   web app / site      Phi mobile app         phi-chain / Go (cgo)
```

`crate-type = ["cdylib", "staticlib", "rlib"]` هر سه خروجی را ممکن می‌کند. هسته‌ی Rust، خروجیِ C-ABI
(مصرف‌شده توسطِ phi-chain) و bindingهای WebAssembly پیاده و آزموده شده‌اند؛ bindingهای باقی‌مانده در
به‌روزرسانی‌های پیشِ‌رو، با سیم‌کشیِ مصرف‌کننده‌هایشان، تکمیل می‌شوند.

## ساخت و تست

مخزن کاملاً خودبسنده است و **آفلاین** ساخته می‌شود: همه‌ی وابستگی‌ها زیرِ `vendor/` بسته‌بندی شده و
`.cargo/config.toml` منابع را به آنجا هدایت می‌کند، پس چیزی هنگامِ ساخت دانلود نمی‌شود.

```bash
cargo test                                   # واحد + یکپارچه (آفلاین، از vendor)
cargo clippy --all-targets -- -D warnings    # باید تمیز باشد
cargo build --release                        # → target/release/libphi_crypto.{a,dylib}
```

### خروجیِ C-ABI (برای phi-chain)

```bash
cargo build --release
cbindgen --config cbindgen.toml --output phi_crypto.h
```

مصرف از Go:

```go
// #cgo LDFLAGS: -L./lib -lphi_crypto
// #include "phi_crypto.h"
import "C"
```

همه‌ی توابعِ راستی‌آزماییِ C-ABI در موفقیت `1` و در غیرِاین‌صورت `0` برمی‌گردانند (fail-safe)؛ هیچ
panic‌ای از مرز عبور نمی‌کند.

### خروجیِ WASM (برای وب)

```bash
cargo build --target wasm32-unknown-unknown        # بررسیِ کامپایل
wasm-pack build --target web --out-dir pkg-web     # بسته‌ی قابلِ‌import وب (نیازمندِ wasm-pack)
```

```js
import init, { bbsDeriveProof, bbsVerifyProof } from "./pkg-web/phi_crypto.js";
await init();
const proof = bbsDeriveProof(claims, signature, Uint32Array.of(3), nonce); // فقط «بالای ۱۸» را فاش کن
const ok = bbsVerifyProof(proof, issuerPublicKey, nonce);
```

خروجیِ WASM را در تولید با Subresource Integrity (SRI) بارگذاری کنید.

## اصولِ امنیتی

- **هرگز رمزنگاری را دستی ننویس** — هر اولیه یک wrapper روی کریتِ بالغ و ممیزی‌شده است.
- `#![deny(unsafe_code)]` همه‌جا به‌جزِ تنها ماژولِ بازبینی‌شده‌ی `ffi`.
- مقایسه‌ی زمان‌ثابتِ مادّه‌ی محرمانه با `subtle` — هرگز `==`؛ کلیدهای محرمانه با `zeroize` پس از
  مصرف صفر می‌شوند.
- امضای low-Sِ اجباری؛ وریفایرها **fail-safe**‌اند — بر هر تردیدی رد می‌کنند.
- `Cargo.lock` کامیت می‌شود و هر کریت pin است؛ ساخت بازتولیدپذیر و آفلاین است.

از افشای مسئولانه استقبال می‌کنیم — آسیب‌پذیری‌ها را خصوصی طبقِ [`SECURITY.md`](./SECURITY.md) گزارش
کنید (**security@portphi.com**)، نه از طریقِ issueِ عمومی.

## ساخته‌شده بر بسترِ

افشای انتخابیِ BBS+ از خانواده‌های **docknetwork/crypto** و **pairing_crypto** (روی arkworks/blst،
BLS12-381)، امضا و هشِ منحنی از **RustCrypto** (`k256`/`p256`/`sha2`)، و مقایسه‌ی زمان‌ثابت از
**subtle**. اسنادِ کامل در [`NOTICE`](./NOTICE) است.

## مجوز

[Apache License 2.0](./LICENSE) — © ۲۰۲۶ شرکت داده هوشمند هومان. تمامیِ حقوق محفوظ است.

طراحی و اختراعِ این پروژه توسطِ **A.Mooraeyan** انجام شده است. پروتکلِ فی و سورسِ اصلیِ این مخزن،
مالکیتِ فکریِ شرکت داده هوشمند هومان است؛ همه‌ی حقوقِ کپی‌رایت و اختراع نزدِ شرکت محفوظ و رزرو است و
شرکت استفاده، مطالعه و بازتوزیعِ نرم‌افزار را تحتِ Apache-2.0 مجاز می‌کند. برای بیانیه‌ی کاملِ
مالکیت، اختراع و علائمِ تجاری [`NOTICE`](./NOTICE) را ببینید.

</div>

---

*Homaan Smart Data Co. — [portphi.com](https://portphi.com)*
