# Miễn trừ trách nhiệm · Disclaimer

**VPN55 is free software under the [MIT licence](LICENSE).** Use it, copy it, change it,
sell it, fork it, ship it inside your own product. No permission needed and none will be
asked for.

The rest of this page is the honest part: what VPN55 does for you, what it cannot do for
you, and where our responsibility ends and yours begins.

---

## Tiếng Việt

### Những gì chúng tôi không bao giờ thấy

VPN55 là công cụ bạn chạy trên **máy chủ của chính bạn**. Đó không phải khẩu hiệu — đó là
toàn bộ kiến trúc, và nó có nghĩa là:

- Chúng tôi không vận hành máy chủ nào. Không có "mạng VPN55" để tham gia, không có tài
  khoản để đăng ký.
- Chúng tôi không giữ dữ liệu nào của bạn. Khoá được tạo ra trên máy của bạn và không bao
  giờ rời khỏi đó.
- Chúng tôi không thấy lưu lượng của bạn — không có đường nào để nó đến được chỗ chúng tôi.
- VPN55 không gửi gì về cho chúng tôi: không thống kê, không kiểm tra phiên bản, không
  "gọi về nhà" ([docs/distribution.md](docs/distribution.md) §1).

Bạn không cần phải tin lời chúng tôi. Mã nguồn ở ngay đây, và đủ ngắn để đọc.

### VPN làm được gì, và không làm được gì

Chúng tôi muốn nói thẳng những điều này, hơn là để bạn phát hiện ra vào đúng lúc không nên:

- **VPN che lưu lượng của bạn khỏi mạng bạn đang dùng, chứ không che khỏi các trang bạn
  truy cập.** Nơi bạn đăng nhập vẫn biết bạn là ai.
- **Nhà cung cấp máy chủ biết máy chủ của bạn tồn tại**, và ở phần lớn các nước họ biết ai
  đã trả tiền cho nó. Hãy cân nhắc điều đó khi chọn nhà cung cấp.
- **Không phải giao thức nào cũng khó chặn như nhau.** IKEv2 dễ nhận diện nhất và thường bị
  chặn trước — VPN55 nói rõ điều đó ngay tại chỗ bạn chọn, chứ không giấu xuống cuối trang
  ([docs/circumvention.md](docs/circumvention.md)).
- **VPN không phải là ẩn danh.** Nếu sự an toàn của bạn phụ thuộc vào việc không bị nhận
  diện, VPN chỉ là một lớp, không phải câu trả lời. Tor được thiết kế cho đúng công việc mà
  VPN không làm.

### Pháp luật, bảo đảm, và giới hạn của chúng tôi

- **Luật về VPN khác nhau ở mỗi quốc gia và mỗi vùng, và luật thay đổi.** Ở một số nơi,
  việc vận hành, sử dụng, hoặc giúp người khác sử dụng VPN có thể bị hạn chế. Chúng tôi
  không thể nói cho bạn biết điều gì áp dụng với bạn — không phải vì chuyện đó không quan
  trọng, mà vì chúng tôi không biết hoàn cảnh của bạn, và một câu trả lời sai còn tệ hơn là
  không trả lời. Xin hãy tìm hiểu trước khi dựa vào nó.
- **Đây không phải là tư vấn pháp lý.** Nếu rủi ro với bạn là lớn, một luật sư hoặc một tổ
  chức về quyền số ở nơi bạn sống sẽ biết những điều chúng tôi không biết.
- **Phần mềm được cung cấp "nguyên trạng", không kèm bảo đảm nào**, và tác giả cùng những
  người đóng góp không thể chịu trách nhiệm pháp lý cho thiệt hại, tổn thất hay hậu quả
  phát sinh từ việc sử dụng. Đây là điều khoản tiêu chuẩn của giấy phép MIT — và cũng là
  điều kiện để phần mềm này được tự do.
- **Bạn dùng nó thế nào là quyền của bạn.** Chúng tôi làm ra một công cụ; nó dùng để làm gì
  là lựa chọn của bạn, và hệ quả cũng vậy.

---

## English

### What we never see

VPN55 is a tool you run on **your own server**. That is not a slogan — it is the entire
architecture, and it means:

- We operate no servers. There is no "VPN55 network" to join and no account to create.
- We hold none of your data. Your keys are generated on your machine and never leave it.
- We see none of your traffic — there is no path by which it could reach us.
- VPN55 sends us nothing: no telemetry, no version check, no phone home
  ([docs/distribution.md](docs/distribution.md) §1).

You do not have to take our word for any of that. The code is right here, and it is short
enough to read.

### What a VPN can and cannot do for you

We would rather say these plainly than let you discover them at a bad moment:

- **A VPN hides your traffic from the network you are on, not from the sites you use.**
  Anywhere you log in still knows who you are.
- **Your server provider knows your server exists**, and in most countries it knows who
  paid for it. Choose one with that in mind.
- **Not every protocol is equally hard to block.** IKEv2 is the easiest to identify and is
  usually blocked first — VPN55 says so at the point where you choose it, rather than
  burying it in a footnote ([docs/circumvention.md](docs/circumvention.md)).
- **A VPN is not anonymity.** If your safety depends on not being identified, a VPN is one
  layer, not the answer. Tor is designed for the job a VPN does not do.

### Law, warranty, and where we stop

- **VPN law differs by country and territory, and it changes.** In some places, operating
  a VPN, using one, or helping someone else use one may be restricted. We cannot tell you
  what applies to you — not because it does not matter, but because we do not know your
  situation, and a wrong answer would be worse than none. Please check before you rely on
  it.
- **This is not legal advice.** If the stakes are high for you, a lawyer or a digital
  rights organisation where you live will know things we do not.
- **The software is provided "as is", without warranty**, and the authors and contributors
  cannot accept liability for loss, damage or legal consequence arising from its use. That
  is the standard MIT position — and the condition on which this software is free.
- **How you use it is yours to decide.** We built a tool; what it is for is your call, and
  so are the consequences.

---

## Français

### Ce que nous ne voyons jamais

VPN55 est un outil que vous faites tourner sur **votre propre serveur**. Ce n'est pas un
slogan — c'est toute l'architecture, et cela veut dire :

- Nous n'exploitons aucun serveur. Il n'y a pas de « réseau VPN55 » à rejoindre, ni de
  compte à créer.
- Nous ne détenons aucune de vos données. Vos clés sont générées sur votre machine et n'en
  sortent jamais.
- Nous ne voyons aucun de vos flux — il n'existe aucun chemin par lequel ils pourraient
  nous parvenir.
- VPN55 ne nous envoie rien : pas de télémétrie, pas de vérification de version, aucun
  appel au serveur ([docs/distribution.md](docs/distribution.md) §1).

Vous n'avez pas à nous croire sur parole. Le code est là, et il est assez court pour être
lu.

### Ce qu'un VPN peut et ne peut pas faire pour vous

Nous préférons vous le dire clairement plutôt que vous le laisser découvrir au mauvais
moment :

- **Un VPN masque votre trafic vis-à-vis du réseau où vous êtes, pas des sites que vous
  utilisez.** Partout où vous vous connectez, on sait toujours qui vous êtes.
- **Votre hébergeur sait que votre serveur existe**, et dans la plupart des pays il sait
  qui l'a payé. Choisissez-le en conséquence.
- **Tous les protocoles ne se bloquent pas aussi facilement.** IKEv2 est le plus simple à
  identifier et sera généralement bloqué en premier — VPN55 le dit là où vous faites le
  choix, et non dans une note de bas de page
  ([docs/circumvention.md](docs/circumvention.md)).
- **Un VPN n'est pas l'anonymat.** Si votre sécurité dépend de ne pas être identifié, un
  VPN est une couche, pas la réponse. Tor est conçu pour ce qu'un VPN ne fait pas.

### Droit, garantie, et là où nous nous arrêtons

- **La législation sur les VPN varie selon les pays et les territoires, et elle évolue.**
  Dans certains, exploiter un VPN, en utiliser un, ou aider quelqu'un à le faire peut être
  restreint. Nous ne pouvons pas vous dire ce qui s'applique à vous — non que cela soit
  sans importance, mais parce que nous ignorons votre situation, et une mauvaise réponse
  serait pire que pas de réponse. Renseignez-vous avant de vous y fier.
- **Ceci n'est pas un avis juridique.** Si les enjeux sont élevés pour vous, un avocat ou
  une organisation de défense des droits numériques près de chez vous saura ce que nous
  ignorons.
- **Le logiciel est fourni « en l'état », sans garantie**, et les auteurs et contributeurs
  ne peuvent accepter de responsabilité pour tout dommage, perte ou conséquence juridique
  découlant de son usage. C'est la position standard de la licence MIT — et la condition à
  laquelle ce logiciel est libre.
- **L'usage que vous en faites vous appartient.** Nous avons fait un outil ; ce à quoi il
  sert est votre choix, et ses conséquences aussi.

---

## Note for maintainers

### Why this file is separate from `LICENSE`

`LICENSE` holds the unmodified MIT text and nothing else. Appending custom terms to the
MIT text would make GitHub's licence detector report `NOASSERTION` instead of `MIT`, which
is how a project stops being obviously safe for others to reuse — the exact problem
documented in [docs/prior-art.md](docs/prior-art.md) for two projects in this space.
Keeping the two files apart preserves both the standard licence *and* the plain-language
explanation.

### Why it is shaped the way it is

The first version of this file was five bullets of what the authors are *not* responsible
for, addressed to a reader who was implicitly a liability. It said "you are entirely
responsible" in bold before it said anything useful, and it answered the one question that
actually frightens a user in a restrictive country — *is this legal for me?* — with "ask a
lawyer", which is not an answer available to most of the people this project is for.

The rewrite follows how projects with the same audience actually write:

- **Mullvad** and **Proton VPN** lead with what they do *not* hold about you, and keep the
  legal text short and in a separate document. Section 1 here is that move: the privacy
  properties were already the strongest thing in the file, buried as a liability bullet.
- **The Tor Project** ("Tor is not enough") and **EFF's Surveillance Self-Defense** state a
  tool's limits as *help to the reader*, not as a disclaimer against them. Section 2 is
  that: it costs nothing, and it is the part a user at real risk needs most.
- **Trail of Bits' Algo** scopes plainly what the tool is and is not for, without a
  liability wall in user-facing text.
- **Nyr** and **angristan**'s installers — our closest MIT prior art
  ([docs/prior-art.md](docs/prior-art.md) §1) — carry essentially no disclaimer beyond
  MIT's own, which is evidence that the long version is a choice, not a requirement.

The warranty and liability text is still here in section 3, unchanged in substance. It is
last, in a neutral voice, and stated as what MIT already says rather than as a warning.

**Do not re-add "you are entirely responsible" as the opening line.** Keep the order:
what we don't see → what a VPN can't do → law and warranty. The three languages stay in
sync, by the same rule as `lib/locales/` ([docs/i18n.md](docs/i18n.md)).

This text is written for clarity, not as vetted legal drafting. If VPN55 is ever monetised
or published under a commercial identity, have a lawyer review it.
