
# Miru-Repo

Miru extensions repository | [Miru App Download](https://github.com/miru-project/miru-app) |

## Develop your own extension

This repo doubles as the extension development bench. See [plug/README.md](plug/README.md).

- The plug/ folder is a plug-and-play test bench for Go (Scriggo V2) extensions.
- Copy an existing extension as your starting point — for Go: repo/golang/rawkuma.go.
- Edit your plug, then run the dual harness: cd plug && go test -v . (or press F5 in
  VS Code — see .vscode/launch.json). Every entry point runs natively AND through
  the Scriggo VM, printing each result as JSON.
- To publish: the plug file must live at repo/golang/<package>.go (Go) or
  repo/js/<package>.js (JavaScript), with the @package header matching the file
  name and @apiVersion 2. The index.json regenerates automatically on push.

> The bench needs a Go >= 1.27 toolchain (the index generator itself is
> stdlib-only). Locally, point the bench at a miru-core checkout via go.work —
> see plug/README.md.

## List
|  Name   | Package | Version | Author | Language | Type | Source |
|  ----   | ---- | --- | ---  | ---  | --- | --- |
| 345movie | 345movie.net | v0.0.3 | qizaru | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/345movie.net.js) |
| 360资源 | 360zy.com | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/360zy.com.js) |
| 9Anime | 9animetv.to | v0.0.3 | appdevelpo | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/9animetv.to.js) |
| AGE动漫 | agedm.org | v0.0.1 | appdevelpo | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/agedm.org.js) |
| AniGoGo | ani.gogo | v0.0.3 | OshekharO | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/ani.gogo.js) |
| AniLiberty | aniliberty | v0.0.9 | Virus (viridius-hub) | ru | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/aniliberty.js) |
| AnimeFlv | anime.flv | v0.0.2 | Yako (koikiss-dev) | es | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/anime.flv.js) |
| girigiri爱动漫 | anime.girigirilove.com | v0.0.4 | appdevelpo | zh | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/anime.girigirilove.com.js) |
| Animeazu | animeazu.com | v0.0.1 | JerukPurut404 | pr | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/animeazu.com.js) |
| Animepahe | animepahe.ru | v0.1.0 | appdevelpo | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/animepahe.ru.js) |
| Animeworld | animeworld | v0.0.1 | Nazz | it | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/animeworld.js) |
| 音悦台MTV | api.yinyuetai | v0.0.2 | vvsolo | zh | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/api.yinyuetai.js) |
| Arabsama | arabsama.net | v0.0.1 | JerukPurut404 | ar | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/arabsama.net.js) |
| AsuraScan | asuratoon.com | v0.0.5 | bethro | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/asuratoon.com.js) |
| 包子漫画 | baozimh.com | v0.0.2 | appdevelpo | zh | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/baozimh.com.js) |
| Bato | bato.to | v0.0.2 | bethro | all | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/bato.to.js) |
| BestLightNovel | best.light.novel | v0.0.1 | anishi7 | en | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/best.light.novel.js) |
| 暴风资源[高清无水印] | bfzy.tv | v0.0.2 | jason | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/bfzy.tv.js) |
| ギリギリ愛 | bgm.girigirilove.com | v0.0.2 | appdevelpo | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/bgm.girigirilove.com.js) |
| 哔哩轻小说 | bilinovel.com | v0.1.0 | hualiong | zh-cn | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/bilinovel.com.js) |
| 笔趣阁 | bqg.cc | v0.0.2 | yxxyun | zh-cn | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/bqg.cc.js) |
| MyIPTV | client.iptv | v0.0.6 | vvsolo | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/client.iptv.js) |
| 动漫之家 | com.dmzj.www | v0.0.2 | MiaoMint | zh-cn | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/com.dmzj.www.js) |
| 欧乐影院 | com.olevod.www | v0.0.1 | MiaoMint | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/com.olevod.www.js) |
| ComicExtra | comicextra | v0.0.2 | OshekharO | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/comicextra.js) |
| Comick | comick.app | v0.0.6 | OshekharO | all | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/comick.app.js) |
| 咕咕影视 | cooing.cc | v0.0.4 | MiaoMint | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/cooing.cc.js) |
| 次元城动漫 | cycanime.com | v0.1.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/cycanime.com.js) |
| media.ccc.de | de.ccc.media | v0.0.1 | Christian Weiske | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/de.ccc.media.js) |
| 7喜影院 | dev.0n0.miru.7xi | v0.0.7 | MiaoMint | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/dev.0n0.miru.7xi.js) |
| DramaCool | dramacool.pa | v0.0.4 | OshekharO | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/dramacool.pa.js) |
| Example Library(V1) | example.v1 | v0.0.1 | appdevelpo | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/example.v1.js) |
| Example Library(V2) | example.v2 | v0.0.1 | appdevelpo | langcode | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/example.v2.js) |
| 非凡资源 | ffzy.tv | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/ffzy.tv.js) |
| FilmyCab | filmycab | v0.0.2 | OshekharO | hi | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/filmycab.js) |
| FilmyPunjab | filmypunjab.com | v0.0.3 | appdevelpo | hi | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/filmypunjab.com.js) |
| FlameComics | flamecomics.com | v0.0.1 | bethro | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/flamecomics.com.js) |
| FlixHQ | flixhq | v0.0.1 | OshekharO | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/flixhq.js) |
| Funtoons | funtoons.online | v0.0.1 | funtoons | th | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/funtoons.online.js) |
| GakiArchives | gakiarchives.com | v0.0.1 | bachig26 | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/gakiarchives.com.js) |
| gimy | gimy.su | v0.0.2 | appdevelpo | zh | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/gimy.su.js) |
| GoGoAnime | gogo.anime | v0.0.8 | OshekharO | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/gogo.anime.js) |
| 古风漫画 | gufengmh | v0.0.1 | 瑜君之学-杨瑜候 | zh | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/gufengmh.js) |
| G站漫画 | gzhanmh | v0.0.1 | 瑜君之学-杨瑜候 | zh | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/gzhanmh.js) |
| 黑木耳资源 | heimuer.tv | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/heimuer.tv.js) |
| HiAnime | hianime.to | v0.0.8 | OshekharO | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/hianime.to.js) |
| 华为吧资源 | huaweiba.live | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/huaweiba.live.js) |
| IDLIX | idlix | v0.0.2 | Nazz | id | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/idlix.js) |
| Invidious | invidious.io | v0.0.4 | OshekharO | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/invidious.io.js) |
| IPTV-ORG | iptv-org | v0.0.1 | vvsolo | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/iptv-org.js) |
| IsekaiScan | isekaiscan.to | v0.0.3 | bethro | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/isekaiscan.to.js) |
| 极速资源 | jisuzy.com | v0.0.2 | SendHX & hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/jisuzy.com.js) |
| 聚小说 | juxiaoshuo | v0.0.1 | OshekharO | zh-cn | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/juxiaoshuo.js) |
| KimCartoon | kimcartoon.li | v0.0.2 | OshekharO | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/kimcartoon.li.js) |
| Kisskh | kisskh.co | v0.0.3 | OshekharO | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/kisskh.co.js) |
| Komiic漫畫 | komiic.com | v0.0.2 | hualiong | zh-tw | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/komiic.com.js) |
| Komikcast | komikcast.lol | v0.0.1 | bethro | all | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/komikcast.lol.js) |
| Komiku.com | komiku.com | v0.0.1 | Nazz | id | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/komiku.com.js) |
| Letv影院 | letv.im | v0.0.1 | appdevelpo | zh | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/letv.im.js) |
| libvio | libvio.app | v0.0.3 | appdevelpo & hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/libvio.app.js) |
| LilyManga | lilymanga.net | v0.0.1 | bethro | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/lilymanga.net.js) |
| LayarKaca | lk21official | v0.0.2 | OshekharO | id | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/lk21official.js) |
| 量子资源 | lzzy.tv | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/lzzy.tv.js) |
| 漫画屋 | manHuaWu | v0.0.1 | 瑜君之学-杨瑜候 | zh | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/manHuaWu.js) |
| MangaLife | manga4life.com | v0.0.1 | appdevelpo | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/manga4life.com.js) |
| MangaBat | mangabat.com | v0.0.1 | bethro | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/mangabat.com.js) |
| MangaClash | mangaclash.com | v0.0.1 | bethro | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/mangaclash.com.js) |
| 拷贝漫画 | mangacopy.com | v0.0.4 | Monster & hualiong | zh-cn | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/mangacopy.com.js) |
| マンガクロス | mangacross.jp | v0.0.1 | OshekharO | jp | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/mangacross.jp.js) |
| MangaDex | mangadex.org | v0.0.3 | bethro | all | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/mangadex.org.js) |
| Mangakatana | mangakatana.com | v0.0.1 | shashankx86 | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/mangakatana.com.js) |
| MangaKomi | mangakomi | v0.0.1 | OshekharO | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/mangakomi.js) |
| Manganato | manganato | v0.0.1 | OshekharO | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/manganato.js) |
| 漫画DB | manhuadb.com | v0.0.1 | ftbom | zh | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/manhuadb.com.js) |
| 漫画柜 | manhuagui.com | v0.0.3 | appdevelpo | zh-cn | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/manhuagui.com.js) |
| Mikanani | me.mikanani | v0.0.4 | MiaoMint | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/me.mikanani.js) |
| Enime | moe.enime | v0.0.5 | MiaoMint | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/moe.enime.js) |
| 轻小说文库 | moe.wol.wenku8 | v0.0.1 | NPGamma | zh-cn | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/moe.wol.wenku8.js) |
| MonosChinos | monoschinos | v0.0.1 | OshekharO | es | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/monoschinos.js) |
| Movieku | movieku.lol | v0.0.3 | appdevelpo | id | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/movieku.lol.js) |
| YTS.mx | mx.yts | v0.0.6 | MiaoMint | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/mx.yts.js) |
| Nimegami | nimegami.id | v0.0.2 | JerukPurut404 | id | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/nimegami.id.js) |
| Nyaa | nyaa.si | v0.0.1 | appdevelpo | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/nyaa.si.js) |
| NyaFun动漫 | nyadm.link | v0.0.6 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/nyadm.link.js) |
| Otakudesu | otakudesu | v0.0.1 | Nazz | id | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/otakudesu.js) |
| Piped | piped.video | v0.0.1 | bethro | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/piped.video.js) |
| Ravenscans | ravenscans.com | v0.0.1 | bethro | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/ravenscans.com.js) |
| rawkuma | rawkuma.com | v0.0.6 | appdevelpo | jp | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/rawkuma.com.js) |
| ReadComicsOnline | readcomicsonline.ru | v0.0.1 | OshekharO | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/readcomicsonline.ru.js) |
| ACG.RIP | rip.acg | v0.0.1 | MiaoMint | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/rip.acg.js) |
| RoyalRoad | royalroad.com | v0.0.3 | appdevelpo | en | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/royalroad.com.js) |
| 樱花动漫 | sakura | v0.0.2 | Monster | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/sakura.js) |
| Samehadaku | samehadaku | v0.0.1 | Nazz | id | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/samehadaku.js) |
| sFlix | sflix.to | v0.0.3 | appdevelpo | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/sflix.to.js) |
| MkvDrama | stream.mkvdrama.org | v0.0.2 | bachig26 | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/stream.mkvdrama.org.js) |
| 速播资源 | subozy.com | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/subozy.com.js) |
| SuperCartoons | supercartoons.net | v0.0.1 | bachig26 | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/supercartoons.net.js) |
| swatmanhua | swatmanhua.com | v0.0.1 | bethro | ar | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/swatmanhua.com.js) |
| TamilYogi | tamilyogi | v0.0.4 | appdevelpo | hi-ta | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/tamilyogi.js) |
| TeamxNovel | teamxnovel.com | v0.0.1 | OshekharO | ar | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/teamxnovel.com.js) |
| MoviesArc | themoviearchive | v0.0.3 | OshekharO | all | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/themoviearchive.js) |
| thunderscans | thunderscans.com | v0.0.1 | bethro | ar | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/thunderscans.com.js) |
| 天空资源网 | tiankongzy.com | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/tiankongzy.com.js) |
| TopCartoons | topcartoons.tv | v0.0.1 | bachig26 | en | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/topcartoons.tv.js) |
| NetTruyen | truyen.net | v0.0.5 | OshekharO | vi | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/truyen.net.js) |
| Turkish123 | turkish123 | v0.0.2 | OshekharO | tr | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/turkish123.js) |
| U酷资源网 | ukuzy.com | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/ukuzy.com.js) |
| Unimay | unimay.media | v0.0.1 | CakesTwix | uk | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/unimay.media.js) |
| Tàng thư viện | vn.tangthuvien | v0.0.1 | Moleys | vi | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/vn.tangthuvien.js) |
| 影视集合 | vod.api.json.collection | v0.0.3 | Horis | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/vod.api.json.collection.js) |
| 八戒影视 | vod.api.xml.bajie | v0.0.1 | Horis | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/vod.api.xml.bajie.js) |
| weebcentral | weebcentral.com | v0.0.2 | bethro | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/weebcentral.com.js) |
| 风车动漫 | windmill | v0.0.1 | Monster | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/windmill.js) |
| Wnmtl | wnmtl.org | v0.0.1 | OshekharO | en | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/wnmtl.org.js) |
| 卧龙资源 | wolongzyw.com | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/wolongzyw.com.js) |
| WTR-LAB | wtr-lab.com | v0.0.1 | OshekharO | en | fikushon | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/wtr-lab.com.js) |
| 无尽资源网 | wujinzy.com | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/wujinzy.com.js) |
| 稀饭动漫 | xfani.com | v0.1.1 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/xfani.com.js) |
| 丫丫资源[1080无水印] | yayazy.net | v0.0.1 | jason | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/yayazy.net.js) |
| 樱花资源 | yhzy.cc | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/yhzy.cc.js) |
| 樱花动漫 CC | yinhuadm | v0.0.1 | Mg | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/yinhuadm.js) |
| YoMovies | yomovies | v0.0.7 | OshekharO | hi | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/yomovies.js) |
| YuriNeko | yurineko.net | v0.0.1 | OshekharO | vi | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/yurineko.net.js) |
| YY漫画 | yymanhua.com | v0.0.4 | hualiong | zh-cn | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/yymanhua.com.js) |
| 优质资源库 | yzzy.tv | v0.0.2 | hualiong | zh-cn | bangumi | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/yzzy.tv.js) |
| ZeroScans | zeroscans.com | v0.0.2 | OshekharO | en | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/zeroscans.com.js) |
| Rawkuma | rawkuma | v0.1.0 | you | ja | manga | [Source Code](https://github.com/miru-project/repo/blob/main/repo/golang/rawkuma.go) |
