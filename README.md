
# Miru-Repo

Miru extensions repository | [Miru App Download](https://github.com/miru-project/miru-app) |

This repository publishes **V2 API** extensions only. See
[docs/V2-API.md](docs/V2-API.md) for the full contract.

## Develop your own extension

This repo doubles as the extension development bench. See [plug/README.md](plug/README.md).

- The plug/ folder is a plug-and-play test bench for Go (Scriggo V2) extensions.
- Copy an existing extension as your starting point — for Go: repo/golang/rawkuma.net.go.
- Edit your plug, then run the dual harness: cd plug && go test -v . (or press F5 in
  VS Code — see .vscode/launch.json). Every entry point runs natively AND through
  the Scriggo VM, printing each result as JSON.
- To publish: the plug file must live at repo/golang/<package>.go (Go) or
  repo/js/<package>.js (JavaScript), with the @package header matching the file
  name and @apiVersion 2. The index.json regenerates automatically on push.

> The bench needs a Go >= 1.27 toolchain (the index generator itself is
> stdlib-only). The V2 runtime (miru-core) is vendored as a git submodule, so
> the bench always builds against the pinned upstream API — run
> git submodule update --init --recursive after cloning.

## List
|  Name   | Package | Version | Author | Language | Type | API | Source |
|  ----   | ---- | --- | ---  | --- | --- | --- | --- |
| Animepahe | animepahe.ru | v0.1.0 | appdevelpo | en | bangumi | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/animepahe.ru.js) |
| ギリギリ愛 | bgm.girigirilove.com | v0.0.2 | appdevelpo | zh-cn | bangumi | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/bgm.girigirilove.com.js) |
| Example Library(V2) | example.v2 | v0.0.1 | appdevelpo | langcode | bangumi | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/example.v2.js) |
| rawkuma | rawkuma.com | v0.0.6 | appdevelpo | jp | manga | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/js/rawkuma.com.js) |
| girigiri愛動漫 | ani.girigirilove.com | v0.1.0 | appdevelpo | zh-cn | bangumi | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/golang/ani.girigirilove.com.go) |
| AnimeGo | animego.me | v0.1.0 | appdevelpo | ru | bangumi | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/golang/animego.me.go) |
| Rawkuma | rawkuma.net | v0.1.0 | appdevelpo | ja | manga | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/golang/rawkuma.net.go) |
| Re:ANIME | reanime.to | v0.1.0 | appdevelpo | en | bangumi | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/golang/reanime.to.go) |
| RoyalRoad | royalroad.com | v0.1.0 | appdevelpo | en | fikushon | 2 | [Source Code](https://github.com/miru-project/repo/blob/main/repo/golang/royalroad.com.go) |
