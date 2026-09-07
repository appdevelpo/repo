// ==MiruExtension==
// @name         Animepahe
// @version      v0.1.0
// @author       appdevelpo
// @lang         en
// @license      MIT
// @icon         https://raw.githubusercontent.com/appdevelpo/repo/refs/heads/miru_alpha/icon/animepahe.ru.png
// @package      animepahe.ru
// @type         bangumi
// @webSite      https://animepahe.com
// @nsfw         false
// @apiVersion   2
// ==/MiruExtension==

var { parseHTML } = require("linkedom");

async function load() {
  await registerSetting({
    title: "Domain",
    key: "domain",
    type: "input",
    description: "Animepahe domain (e.g., https://animepahe.com)",
    defaultValue: "https://animepahe.com",
  });
}

async function getDomain() {
  return (await getSetting("domain")) || "https://animepahe.com";
}

async function latest(page) {
  const domain = await getDomain();
  try {
    const res = await fetch(`${domain}/api?m=airing&page=${page}`);
    const json = await res.json();
    return json.data.map((item) => ({
      title: item.anime_title,
      url: item.anime_session.toString(),
      cover: item.snapshot,
    }));
  } catch (e) {
    console.log(e.toString());
    return [
      {
        title: "Error fetching latest",
        url: "/",
        cover: null,
      },
    ];
  }
}

async function search(kw, page) {
  const domain = await getDomain();
  const res = await fetch(`${domain}/api?m=search&q=${kw}`);
  const json = await res.json();
  return json.data.map((item) => ({
    title: item.title,
    url: item.session.toString(),
    cover: item.poster,
  }));
}

async function detail(url) {
  if (url === "/") {
    return {
      title: "Blocked",
      cover: null,
      desc: "Please use webview to enter the website then close the webview window.",
    };
  }
  const domain = await getDomain();
  const res = await fetch(`${domain}/anime/${url}`);
  const html = await res.text();
  const { document } = parseHTML(html);

  const coverElement = document.querySelector(".anime-poster > * > img");
  const cover = coverElement ? coverElement.getAttribute("data-src") : null;

  const titleElement = document.querySelector(".user-select-none > span");
  const title = titleElement ? titleElement.innerHTML : "Unknown Title";

  const descMatch = html.match(/<div class="anime-synopsis">(.+?)<\/div>/);
  const desc = descMatch ? descMatch[1] : "";

  const epRes = await fetch(`${domain}/api?m=release&id=${url}`);
  const epJson = await epRes.json();
  const reverse_data = epJson.data.reverse();

  return {
    title: title,
    cover: cover,
    desc: desc,
    episodes: [
      {
        title: "Episodes",
        urls: reverse_data.map((item) => ({
          name: `Episode ${item.episode}`,
          url: `${url}/${item.session}`,
        })),
      },
    ],
  };
}

async function watch(url) {
  const domain = await getDomain();
  const res = await fetch(`${domain}/play/${url}`);
  const html = await res.text();
  const { document } = parseHTML(html);
  const buttons = document.querySelectorAll("#resolutionMenu > button");

  const groups = {};
  buttons.forEach((btn) => {
    const fansub = btn.getAttribute("data-fansub");
    const resolution = btn.getAttribute("data-resolution");
    const src = btn.getAttribute("data-src");
    if (!groups[fansub]) groups[fansub] = [];
    groups[fansub].push({
      name: resolution + "p",
      url: src,
    });
  });

  return {
    groups: Object.keys(groups).map((title) => ({
      title: title,
      mirrors: groups[title],
    })),
  };
}

async function mirror(url) {
  const res = await fetch(url, {
    headers: {
      Referer: "https://animepahe.com",
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56",
    },
  });

  const html = await res.text();
  const hid_script = html.match(/eval\(f.+?\}\)\)/g)[1];
  const decode_script = eval(hid_script.match(/eval(.+)/)[1]);
  const decode_url = decode_script.match(/source='(.+?)'/)[1];

  return {
    type: "hls",
    url: decode_url,
    headers: {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/10100101 Firefox/146.0",
      Accept: "*/*",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      Origin: "https://kwik.cx",
      "Sec-GPC": "1",
      Connection: "keep-alive",
      Referer: "https://kwik.cx/",
      "Sec-Fetch-Dest": "empty",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "cross-site",
    },
  };
}
