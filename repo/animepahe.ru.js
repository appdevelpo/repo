// ==MiruExtension==
// @name         Animepahe
// @version      v0.0.5
// @author       appdevelpo
// @lang         en
// @license      MIT
// @icon         https://raw.githubusercontent.com/appdevelpo/repo/refs/heads/miru_alpha/icon/animepahe.ru.png
// @package      animepahe.ru
// @type         bangumi
// @webSite      https://animepahe.si
// @nsfw         false
// ==/MiruExtension==

export default class extends Extension {
  async search(kw) {
    const res = await this.request(`/api?m=search&q=${kw}`);
    // console.log(res);
    return res.data.map((item) => ({
      title: item.title,
      url: item.session.toString(),
      cover: item.poster,
    }));
  }

  async latest(page) {
    try {
      const res = await this.request(`/api?m=airing&page=${page}`);
      console.log(res);
      return res.data.map((item) => ({
        title: item.anime_title,
        url: item.anime_session.toString(),
        cover: item.snapshot,
      }));
    } catch (e) {
      console.log(e.toString());
      const bangumi = [{
        title: "error",
        url: "/",
        cover: null
      }];
      return bangumi;
    }
  }

  async detail(url) {
    if (url == "/") {
      return {
        title: "Blocked",
        cover: null,
        desc: "Please use webview to enter the website then close the webview window.",
      }
    }
    const {parseHTML} = require("linkedom")
    const res = await this.request(`/anime/${url}`);
    const select = await this.querySelector(res, '.user-select-none > span');
    const { document } = parseHTML(res);
    const c = document.querySelector('.anime-poster > * > img');
    const cover = c ? c.getAttribute('data-src') : null;

    const title = select.innerHTML;
    console.log(title)
    // const imgselect = this.querySelector(res, '.poster-image');
    // console.log(imgselect.text);
    // const cover = imgselect.getAttributeText('herf');
    console.log(cover);
    const desc = res.match(/<div class="anime-synopsis">(.+?)<\/div>/)[1];
    const epRes = await this.request(`/api?m=release&id=${url}`)
    // console.log(title[1]);
    const reverse_data = epRes.data.reverse();
    return {
      title: title,
      cover: cover,
      desc: desc,
      episodes: [
        {
          title: "SubsPlease-360p",
          urls: reverse_data.map((item) => ({
            name: `Episode ${item.episode}`,
            url: `${url}/${item.session};0`,//url;quality
          })),
        },
        {
          title: "SubsPlease-720p",
          urls: reverse_data.map((item) => ({
            name: `Episode ${item.episode}`,
            url: `${url}/${item.session};1`,
          })),
        },
        {
          title: "SubsPlease-1080p",
          urls: reverse_data.map((item) => ({
            name: `Episode ${item.episode}`,
            url: `${url}/${item.session};2`,
          })),
        },
      ],
    };
  }

  async watch(url) {
    // console.log(url);
    const url_split = url.split(';');
    const res = await this.request(`/play/${url_split[0]}`)
    // console.log((/data-src="https:\/\/kwik.cx.+?"/g).exec(res)[parseInt(url_split[1])]);
    // console.log(res.match(/data-src="https:\/\/kwik.cx.+?"/g))
    // const src_match = res.match(/data-src="https:\/\/kwik.cx.+?"/g)[parseInt(url_split[1])]; //480,720,1080 === [0],[1],[2]
    // console.log(src_match);
    console.log(url_split[1]);
    console.log(res.match(/data-src="(https:\/\/kwik\.cx.+?)"/g))
    const src = res.match(/data-src="(https:\/\/kwik\.cx.+?)"/g)[parseInt(url_split[1])].match(/data-src="(.+?)"/)[1];
    console.log(src);
    const hid_res = await this.request("", {
      headers: {
        "Miru-Url": src,
        "Referer": "https://animepahe.com",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56"
      }
    })
    const hid_script = hid_res.match(/eval\(f.+?\}\)\)/g)[1];
    const decode_script = eval(hid_script.match(/eval(.+)/)[1]);
    // the obfuscated script look like eval(function(p,a,c,k,e,d){e=function(c){return(c<a?......
    const decode_url = decode_script.match(/source='(.+?)'/)[1];
    return {
      type: "hls",
      url: decode_url,
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Origin": "https://kwik.cx",
        "Sec-GPC": "1",
        "Connection": "keep-alive",
        "Referer": "https://kwik.cx/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"
      }
    };
  }
}

