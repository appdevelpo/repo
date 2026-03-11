// ==MiruExtension==
// @name         ギリギリ愛
// @version      v0.0.2
// @author       appdevelpo
// @lang         zh-cn
// @license      MIT
// @icon         https://raw.githubusercontent.com/appdevelpo/repo/refs/heads/miru_alpha/icon/bgm.girigirilove.com.png
// @package      bgm.girigirilove.com
// @type         bangumi
// @webSite      https://bgm.girigirilove.com/
// @nsfw         false
// @apiVersion   2
// ==/MiruExtension==

var latest = async () => {
    try {
        var {parseHTML} = require("linkedom")
        const res = await fetch(
            "https://bgm.girigirilove.com/show/2-----------/",
        );
        const text = await res.text();
        const { document } = parseHTML(text);
        
        const item = document.querySelectorAll(
            "div.public-pic-b.public-list-box",
        );

        const bangumi = item.map((element) => {
            const url = element.querySelector(".public-list-exp")
                ?.getAttribute("href");
            const img = element.querySelector(".public-list-exp > img");
            const cover = "https://bgm.girigirilove.com" +
                    img?.getAttribute("data-src") ||
                img?.getAttribute("src");
            const title = element.querySelector(".ft4.hide.time-title")
                ?.textContent.trim();
            const update = element.querySelector(
                ".ft2.hide.cor5.public-list-subtitle",
            )
                ?.textContent.trim();
            return {
                cover,
                title,
                url,
                update,
            };
        });
        return bangumi;
    } catch (error) {
        console.error("Error fetching or parsing:", error);
        throw error;
    }
};

var search = async (kw, page) => {
    var {parseHTML} = require("linkedom")
    try {
        const res = await fetch(
            `https://bgm.girigirilove.com/search/${kw}----------${page}---/`,
        );
        const text = await res.text();
        const { document } = parseHTML(text);
        const item = document.querySelectorAll(
            ".overflow.rel.flex",
        );

        const bangumi = item.map((element) => {
            const url = element.querySelector("a.button")
                ?.getAttribute("href");
            const img = element.querySelector(".detail-pic > img");
            const cover = "https://bgm.girigirilove.com" +
                    img?.getAttribute("data-src") ||
                img?.getAttribute("src");
            const title = element.querySelector(".hide.slide-info-title")
                ?.textContent.trim();
            const description = element.querySelectorAll(
                "span.slide-info-remarks",
            )
                ?.map((el) => el.textContent.trim()).join("-");
            return { url, cover, title, description };
        });
        return bangumi;
    } catch (error) {
        console.error("Error fetching or parsing:", error);
    }
};

var detail = async (url) => {
    var {parseHTML} = require("linkedom")
    try {
        const res = await fetch(`https://bgm.girigirilove.com${url}`);
        const text = await res.text();
        const { document } = parseHTML(text);
        const title = document.querySelector(".hide.slide-info-title")
            ?.textContent
            .trim();
        const desc =
            document.querySelector("#height_limit")?.textContent.trim() ||
            document.querySelector(".detail-intro-all")?.textContent.trim() ||
            document.querySelector(".selected.check")?.textContent.trim();
        const cover = "https://bgm.girigirilove.com" +
                document.querySelector(".detail-pic > img")?.getAttribute(
                    "data-src",
                ) ||
            document.querySelector(".detail-pic > img")?.getAttribute("src");

        const sources = Array.from(
            document.querySelectorAll(".anthology-tab .swiper-slide"),
        ).map((el) => {
            return el.textContent.trim().replace(/\d+$/, "").trim();
        });

        const episodeLists = Array.from(
            document.querySelectorAll(".anthology-list-box"),
        );

        const episodes = sources.map((source, index) => {
            const listEl = episodeLists[index];
            if (!listEl) return null;

            const urls = Array.from(listEl.querySelectorAll(".this-link")).map(
                (link) => {
                    return {
                        name: link.textContent.trim(),
                        url: "https://bgm.girigirilove.com" +
                            link.getAttribute("href"),
                    };
                },
            );

            return {
                title: source,
                urls: urls,
            };
        }).filter((e) => e !== null);

        return {
            title,
            desc,
            cover,
            episodes,
        };
    } catch (error) {
        console.error("Error in detail:", error);
        return null;
    }
};

var watch = async (url) => {
    try {
        const res = await fetch(url);
        const text = await res.text();

        const match = text.match(/var player_aaaa\s*=\s*({.+?})\s*</);
        if (!match) {
            return null;
        }

        const json = JSON.parse(match[1]);
        let videoUrl = json.url;

        if (json.encrypt === 2) {
            videoUrl = decodeURIComponent(atob(videoUrl));
        } else {
            videoUrl = decodeURIComponent(videoUrl);
        }

        return {
            type: "hls",
            url: videoUrl,
        };
    } catch (error) {
        console.error("Error in watch:", error);
        return null;
    }
};
