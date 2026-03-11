// ==MiruExtension==
// @name         rawkuma
// @version      v0.0.5
// @author       appdevelpo
// @lang         jp
// @license      MIT
// @type         manga
// @package      rawkuma.com
// @webSite      https://rawkuma.net
// @nsfw         false
// @apiVersion   2
// @icon         https://raw.githubusercontent.com/appdevelpo/repo/refs/heads/miru_alpha/icon/rawkuma.png
// ==/MiruExtension==

var baseUrl = "https://rawkuma.net";

var latest = async () => {
  try {
    var {parseHTML} = require("linkedom")
    const res = await fetch(baseUrl);
    console.log(res)
    const text = await res.text();
    const { document } = parseHTML(text);

    const h2s = Array.from(document.querySelectorAll("h2"));
    const latestUpdateHeader = h2s.find((h) =>
      h.textContent.includes("Latest Update")
    );
    if (!latestUpdateHeader) return [];

    const container = latestUpdateHeader.closest(".project") ||
      latestUpdateHeader.parentElement.parentElement;
    let items = container.querySelectorAll(".p-2.5 .flex.gap-3");
    if (items.length === 0) {
      items = container.querySelectorAll(".grid > div");
    }

    return Array.from(items).map((element) => {
      const urlEl = element.querySelector('a[href*="/manga/"]');
      const url = urlEl?.getAttribute("href")?.replace(baseUrl, "");
      const img = element.querySelector("img");
      const cover = img?.getAttribute("src");
      const title = element.querySelector("h4")?.textContent.trim() ||
        element.querySelector("h3")?.textContent.trim() ||
        element.querySelector("h1")?.textContent.trim() ||
        urlEl?.getAttribute("title") ||
        urlEl?.textContent.trim();
      const description = element.querySelector("li")?.textContent.trim() ||
        "";

      return { url, cover, title, description };
    }).filter((item) => item.url && item.title);
  } catch (error) {
    console.error("Error in latest:", error);
    throw error;
  }
};

var search = async (kw, page) => {
  var {parseHTML} = require("linkedom")
  try {
    const url = page > 1
      ? `${baseUrl}/manga/page/${page}/?title=${kw}`
      : `${baseUrl}/manga/?title=${kw}`;
    const res = await fetch(url);
    const text = await res.text();
    const { document } = parseHTML(text);

    const items = document.querySelectorAll(".grid > div");

    return Array.from(items).map((element) => {
      const urlEl = element.querySelector('a[href*="/manga/"]');
      const url = urlEl?.getAttribute("href")?.replace(baseUrl, "");
      const img = element.querySelector("img");
      const cover = img?.getAttribute("src");
      const title = element.querySelector("h1")?.textContent.trim() ||
        element.querySelector("h2")?.textContent.trim() ||
        element.querySelector("h3")?.textContent.trim() ||
        element.querySelector("h4")?.textContent.trim() ||
        element.querySelector(".font-medium")?.textContent.trim() ||
        urlEl?.getAttribute("title") ||
        urlEl?.textContent.trim();

      const description = "";

      return { url, cover, title, description };
    }).filter((item) => item.url && item.title);
  } catch (error) {
    console.error("Error in search:", error);
    return [];
  }
};

var detail = async (url) => {
  var {parseHTML} = require("linkedom")
  try {
    const fullUrl = url.startsWith("http") ? url : `${baseUrl}${url}`;
    const res = await fetch(fullUrl);
    const text = await res.text();
    const { document } = parseHTML(text);

    const title = document.querySelector('h1[itemprop="name"]')?.textContent
      .trim();
    const cover = document.querySelector("img.wp-post-image")?.getAttribute(
      "src",
    );
    const desc = document.querySelector('meta[name="description"]')
      ?.getAttribute("content") ||
      document.querySelector(".entry-content")?.textContent.trim() || "";

    const chapterListEl = document.querySelector("#chapter-list");
    const hxGet = chapterListEl?.getAttribute("hx-get");
    const mangaIdMatch = hxGet?.match(/manga_id=(\d+)/);

    let episodes = [];
    if (mangaIdMatch) {
      const mangaId = mangaIdMatch[1];
      const chaptersRes = await fetch(
        `${baseUrl}/wp-admin/admin-ajax.php?manga_id=${mangaId}&page=1&action=chapter_list`,
      );
      const chaptersText = await chaptersRes.text();
      const { document: chaptersDoc } = parseHTML(chaptersText);

      const chapterLinks = Array.from(chaptersDoc.querySelectorAll("a"))
        .filter(
          (a) => a.getAttribute("href")?.includes("/chapter-"),
        );

      const urls = chapterLinks.map((a) => {
        const name = a.querySelector("span")?.textContent.trim() ||
          a.textContent.trim().split("\n")[0].trim();
        const updateStr = a.querySelector("time")?.getAttribute(
          "datetime",
        );
        let update = null;
        if (updateStr) {
          try {
            update = new Date(updateStr).toISOString();
          } catch (e) {}
        }
        const description = a.querySelector(".text-gray-400")
          ?.textContent.trim();

        return {
          name,
          url: a.getAttribute("href"),
          update,
          description,
        };
      });

      episodes = [{
        title: "Chapters",
        urls: urls,
      }];
    }

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
  var {parseHTML} = require("linkedom")
  try {
    const res = await fetch(url);
    const text = await res.text();
    const { document } = parseHTML(text);

    const images = Array.from(
      document.querySelectorAll('img[src*="rcdn.kyut.dev"]'),
    )
      .map((img) => img.getAttribute("src"))
      .filter((src) => src);

    return {
      type: "manga",
      urls: images,
    };
  } catch (error) {
    console.error("Error in watch:", error);
    return null;
  }
};
