<h1 align="center">VPN55</h1>

<p align="center">
  <b>Một máy chủ VPN của riêng bạn — WireGuard, IKEv2 và OpenVPN, một lệnh cài đặt, một trang quản trị.</b><br>
  <sub>Your own VPN server — WireGuard, IKEv2 and OpenVPN behind one install command and one admin panel.</sub>
</p>

<p align="center">
  <a href="#cài-đặt--install"><img alt="install" src="https://img.shields.io/badge/install-one%20command-B4552A?style=flat-square"></a>
  <img alt="protocols" src="https://img.shields.io/badge/protocols-WireGuard%20%C2%B7%20IKEv2%20%C2%B7%20OpenVPN-16191D?style=flat-square">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-1F7A5C?style=flat-square">
  <img alt="status" src="https://img.shields.io/badge/status-pre--release-96650B?style=flat-square">
</p>

<p align="center">
  <b>Tiếng Việt</b> · English · Français
</p>

---

<!-- ─────────────────────────────────────────────────────────────────────────
     TERMINAL GIF — replace this block with the recording.

       docs/media/install.gif   ·  ~1200px wide  ·  under 8 MB
       Record with asciinema + agg, or vhs. Show the real thing:
       `vpn55.sh` → pick WireGuard → add a user → QR code on screen.
       Under 30 seconds. No cuts, no speed-up — the point is that it is
       genuinely that short.
     ───────────────────────────────────────────────────────────────────── -->

<p align="center">
  <img src="docs/media/install.gif" alt="Cài đặt VPN55 trong 30 giây" width="820">
</p>

<p align="center"><sub><i>⬆ placeholder — terminal recording goes here</i></sub></p>

---

## Cài đặt · Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/noobvie/VPN55/main/vpn55.sh)
```

Chạy với quyền `root` trên một VPS mới. Không cần Docker, không cần tài khoản, không
gửi dữ liệu đi đâu cả.

> Run as `root` on a fresh VPS. No Docker, no account, nothing phones home.
> Everything the installer creates stays on your machine — see
> **[docs/security-model.md](docs/security-model.md)**.

<sub>This URL is the **canonical** install path and never changes. It is served from
GitHub, not from `vpn55.org` — the website is a convenience, not a dependency. If the
site is unreachable from your network, this command still works.</sub>

<details>
<summary><b>Nếu GitHub bị chặn · If the code host is blocked</b></summary>

Mọi thứ VPN55 tải về đều đến từ **một URL gốc duy nhất**. Đổi biến đó là đủ — không cần
bản cài đặt mới:

```bash
VPN55_MIRROR=https://mirror.example/VPN55 \
  bash <(curl -fsSL https://mirror.example/VPN55/vpn55.sh)
```

> Everything the installer fetches comes from **one base URL**, and that URL is a
> variable. Any static host works — another code host, a plain web directory, an onion
> service behind `torsocks`. The current mirrors are listed in this README, which is the
> root of trust; a site that lists its own mirrors dies with them.
>
> The installer copies itself to `/usr/local/lib/vpn55`. After that, `vpn55.sh --update`
> refreshes it from the same base URL and **stops**, because bash is still running the
> code it parsed at launch.

</details>

---

## Vì sao VPN55 · Why VPN55

**Ba giao thức, một trình quản lý.** Không phải ba trình cài đặt rời rạc, mỗi cái
một kiểu quản lý người dùng.

| | |
|---|---|
| 🇻🇳 **Tiếng Việt là mặc định** | Giao diện đầy đủ tiếng Việt, không phải bản dịch máy gắn thêm sau — kể cả hướng dẫn cài đặt gửi kèm cho người dùng. English và Français cũng có sẵn. ([docs/i18n.md](docs/i18n.md)) |
| 🔀 **Ba giao thức song song** | WireGuard cho tốc độ, IKEv2 cho máy không cần cài app, OpenVPN TCP/443 cho mạng chặn UDP. |
| 👤 **Một người, một hồ sơ** | Một người dùng có thể có chứng thư cho cả ba giao thức. Danh sách người dùng là một, không phải ba. |
| 📊 **Thống kê không bị mất** | Lưu lượng được cộng dồn qua mỗi lần khởi động lại, không bị đặt lại về 0. |
| 🔐 **Panel không phải là root** | Trang quản trị gọi một trình trợ giúp có danh sách lệnh cố định. Panel bị chiếm không đồng nghĩa với mất máy chủ. |
| 🙋 **Trang tự phục vụ** | Người dùng tự tải cấu hình, tự xem dung lượng, tự đổi khóa. Bạn không phải làm thủ công. |

---

## Bảng điều khiển · The panel

<!-- ─────────────────────────────────────────────────────────────────────────
     PANEL SCREENSHOT — replace this block.

       docs/media/panel.png   ·  2x DPI  ·  dark theme
       Show the users list with all three protocols visible in one table —
       that is the whole product thesis in one image. Use realistic
       Vietnamese names and non-round traffic figures; obviously-fake demo
       data reads as vapourware.
     ───────────────────────────────────────────────────────────────────── -->

<p align="center">
  <img src="docs/media/panel.png" alt="Bảng điều khiển VPN55" width="900">
</p>

<p align="center"><sub><i>⬆ placeholder — panel screenshot goes here</i></sub></p>

---

## Hệ điều hành hỗ trợ · Supported distributions

| Distribution | Versions | WireGuard | IKEv2 | OpenVPN | Status |
|---|---|:--:|:--:|:--:|---|
| Debian | 11, 12 | — | — | — | 🚧 planned |
| Ubuntu | 20.04, 22.04, 24.04 | — | — | — | 🚧 planned |
| Rocky Linux | 9, 10 | — | — | — | 🚧 planned |
| AlmaLinux | 9, 10 | — | — | — | 🚧 planned |
| CentOS Stream | 9 | — | — | — | 🚧 planned |
| Fedora | 40+ | — | — | — | 🚧 planned |
| Arch Linux | rolling | — | — | — | 🚧 planned |
| Oracle Linux | 9 | — | — | — | 🚧 planned |

**Nothing in this table is tested yet.** VPN55 is pre-release: the matrix lists what
the build targets, not what has been verified. Claiming an untested distro is how the
first issue gets filed.

A row turns ✅ only when [`tests/vps-acceptance.sh`](tests/vps-acceptance.sh) has passed
on that distribution — install three times over, uninstall, and the host left byte-for-byte
as it was found, with its route out and its SSH port intact. The run prints one
machine-readable line, and that line is the evidence for the row:

```bash
# On a throwaway VPS, as root, over SSH:
./tests/vps-acceptance.sh --yes-destroy-this-host
```

It does **not** connect a client. A tunnel that installs reversibly is not a tunnel that
carries traffic, and no row here claims it does on the strength of that script alone —
see [tests/README.md](tests/README.md).

**Containers:** OpenVZ and some LXC hosts cannot load the WireGuard kernel module.
VPN55 detects this and tells you plainly, rather than failing halfway through.

---

## Trạng thái · Status

Pre-release. **Phase 9 of 9** — everything is written: the installer, the user
registry, the shared certificate authority, all three protocol adapters, the admin
panel, the self-serve portal and the three locales.

**None of it has been run on a real server yet.** Every phase below is complete as
*code*; not one is complete as *evidence*. The command above installs software that has
never started a daemon, and the distribution matrix above is empty for exactly that
reason. The honest version is in [docs/security-model.md](docs/security-model.md) §7 —
read it before you point traffic at this.

| Phase | | |
|---|---|---|
| 0 | Scaffold | ✅ |
| 1 | Core libraries | ✅ |
| 2 | WireGuard adapter | ✅ |
| 3 | IKEv2/IPsec adapter | ✅ |
| 4 | OpenVPN adapter | ✅ |
| 5 | Panel — read-only | ✅ |
| 6 | Panel — write actions | ✅ |
| 7 | Internationalisation | ✅ |
| 8 | Self-serve portal | ✅ |
| 9 | Launch readiness | 🚧 written, unrun |

What Phase 9 still owes is not code: a VPS run of the acceptance harness on each
distribution claimed, a signing key, and the mirrors below. See
[docs/launch.md](docs/launch.md).

---

## Bảo mật · Security

VPN55 is infrastructure you point your traffic through, so the honest version of
"how it works" is a feature, not an appendix:

**→ [docs/security-model.md](docs/security-model.md)** — who holds which key, what
the panel can and cannot do, and exactly what a panel compromise costs you.

Found something? Open a security advisory rather than a public issue.

---

## Kiểm tra bản tải về · Verify what you install

<!-- ─────────────────────────────────────────────────────────────────────────
     PUBLIC KEY — replace the placeholder with the real minisign public key.
     It belongs HERE, in the README, and not only on the website: the README
     lives on the host that cannot be blocked. Generate the pair once, keep
     the secret half offline:   minisign -G -p vpn55.pub -s vpn55.key
     ───────────────────────────────────────────────────────────────────── -->

```
minisign public key: RWQ................................................
```

<sub><i>⬆ placeholder — the real key goes here before the first tagged release</i></sub>

**Tiếng Việt.** Nếu bạn tải VPN55 từ bất kỳ nơi nào khác ngoài kho mã này, hãy kiểm tra
trước khi chạy bằng quyền `root`:

```bash
curl -fsSLO https://raw.githubusercontent.com/noobvie/VPN55/main/SHA256SUMS
curl -fsSLO https://raw.githubusercontent.com/noobvie/VPN55/main/SHA256SUMS.minisig
minisign -Vm SHA256SUMS -P '<khóa công khai ở trên>'   # chữ ký của tác giả
sha256sum -c SHA256SUMS                                # nội dung khớp chữ ký
```

Hai lệnh, hai việc khác nhau: `minisign` chứng minh **ai** đã phát hành, `sha256sum`
chứng minh **tệp không bị sửa**. Thiếu một trong hai là chưa kiểm tra.

> **`curl … | bash` không thể tự kiểm tra chính nó.** Khi script có thể kiểm tra chữ ký
> thì nó đã chạy bằng quyền `root` rồi. Chữ ký giải quyết vấn đề **bản sao** — nó cho
> phép người tìm thấy VPN55 ở nơi khác chứng minh đó đúng là bản đã phát hành. Nó không
> biến lệnh một dòng thành an toàn, và ai nói ngược lại là đang bán một bảo đảm không
> tồn tại.
>
> **In English:** `curl | bash` cannot verify itself — by the time the script could check
> a signature it is already running as root. Signing fixes the *mirror* problem, not that
> one. The one-line install is the convenience path; the four commands above are the
> recommended one. Full reasoning: [docs/distribution.md](docs/distribution.md) §5.

An installed copy can also check itself against the file list it was fetched with:

```bash
/usr/local/lib/vpn55/vpn55.sh --verify
```

That catches corruption and accidental edits. It does not catch a mirror that served a
consistent lie — only the signature above does that.

---

## Mirrors · Bản sao

**This README is the root of trust, not the website.** A site that lists its own mirrors
disappears together with them.

| | |
|---|---|
| Code host (canonical) | `https://github.com/noobvie/VPN55` |
| Raw base URL (`VPN55_MIRROR`) | `https://raw.githubusercontent.com/noobvie/VPN55/main` |
| Landing page | `https://vpn55.org` · `https://noobvie.github.io/VPN55` |
| Git mirror | *(to be added — Codeberg or GitLab)* |
| Onion service | *(to be added)* |
| Announcements | *(to be added — Telegram channel)* |

<sub>Every entry marked *to be added* is outstanding, not omitted. Until they exist, one
DNS block is one point of failure — see [docs/launch.md](docs/launch.md).</sub>

---

## Giấy phép · License

**MIT.** See [LICENSE](LICENSE). Use it, copy it, change it, sell it, fork it — no
permission needed.

> **VPN55 chạy trên máy chủ của bạn.** Chúng tôi không vận hành máy chủ nào, không giữ dữ
> liệu nào của bạn, và không thấy lưu lượng của bạn — không có đường nào để nó đến được
> chỗ chúng tôi. Đổi lại: luật về VPN khác nhau ở mỗi quốc gia và chúng tôi không thể tư
> vấn cho hoàn cảnh của bạn, phần mềm được cung cấp "nguyên trạng" không kèm bảo đảm, và
> bạn dùng nó thế nào là quyền — cũng như trách nhiệm — của bạn.
>
> **VPN55 runs on your server.** We operate no servers, hold none of your data, and see
> none of your traffic — there is no path by which it could reach us. In return: VPN law
> differs by country and we cannot advise you on your situation, the software is provided
> "as is" without warranty, and how you use it is your call and your responsibility.

Full text, in Tiếng Việt / English / Français → **[DISCLAIMER.md](DISCLAIMER.md)**

Third-party code and its licences → [ATTRIBUTIONS.md](ATTRIBUTIONS.md) ·
[docs/prior-art.md](docs/prior-art.md)
