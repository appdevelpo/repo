// ==MiruExtension==
// @name         yugenanime
// @version      v0.0.1
// @author       appdevelpo
// @lang         en
// @license      MIT
// @type         bangumi
// @icon         https://yugenanime.tv/static/img/favicon-32x32.png
// @package      yugenanime.tv
// @webSite      https://yugenanime.tv
// @nsfw         false
// @api          2
// @status       1
// @tags          anime,english
// ==/MiruExtension==

var search = async(kw, page) =>{
    Miru.snackbar("searching");
    const res = await Miru.request(`/discover/?page=${page}&q=${kw}`);
    const {document:doc} = parseHTML(res);
    const bsxList = doc.querySelectorAll("a.anime-meta");
    const mangas = [];
    bsxList.forEach(element => {
        const url = element.getAttribute("href");
        const title = element.getAttribute("title");
        const cover = element.querySelector("img").getAttribute("data-src");
        mangas.push({
            title,
            url,
            cover,
        });
    });
    return mangas;

}
var detail = async(url) =>{
    Miru.snackbar("This is detail");
    const res = await Miru.request(`${url}watch`);
    const {document:doc} = parseHTML(res);
    const title = doc.querySelector(".content > .p-10-t").innerHTML;
    const cover = doc.querySelector("img.cover").getAttribute("src");
    const desc = doc.querySelector(".p-10-t.description").innerHTML;
    const bsxList = doc.querySelectorAll(".ep-card");
    const urls = []
    bsxList.forEach(element => {
        const name = element.querySelector("a.ep-title").innerHTML;
        const url = element.querySelector("a.ep-title").getAttribute("href");
        urls.push({
            name,
            url
        })
    });
    return {
        title: title.replace(/\r|\n|\t/g, ""),
        cover,
        desc,
        episodes: [{ title: "", urls }]
    }
}
var watch = async(url) =>{
    const res = await Miru.request(url);
    Miru.snackbar("you are watching the video, please wait a moment");
    const {document:doc} = parseHTML(res);
    const embedSelector = doc.querySelector("#main-embed").getAttribute("src");
    console.log(embedSelector)
    const id = embedSelector.match(/\/e\/(.+)/)[1]
    console.log(id)
    const body = {
        id:id, ac: 0
    }
    const apiRes = await Miru.request("", {
        method: "POST",
        data: body,
        headers: {
            "Miru-Url": "https://yugenanime.tv/api/embed/",
            "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With":"XMLHttpRequest",
            "Referer":`https://yugenanime.tv/e/${id}/`,
        }
    });
    const videoLink = apiRes.hls
    return{
        type:"hls",
        url:videoLink[0],
    }

}
var latest = async(page) =>{
    Miru.snackbar("Loading...");
    const a = await Miru.saveData("test", "this saving test")
    console.log(a)
    const b = await Miru.getData("test")
    console.log(b)
    const re = await Miru.rawRequest(`https://yugenanime.tv/latest/?page=${page}`)
    console.log(re.headers)
    var  cookie = await Miru.listCookies();
    console.log(cookie)
    const result = await Miru.setCookie("csrftoken=NutCsth2Ma6yXMqQMZMJJIzYZSzlS0000ffff  ")
    console.log(result)
    var  cookie = await Miru.listCookies();
    console.log(cookie)
    const res = await Miru.request(`/latest/?page=${page}`);
    const {document:doc} = parseHTML(res);
    const bsxList = doc.querySelectorAll("li.ep-card"); 
    const mangas = [];
    bsxList.forEach(element => {
        const url = element.querySelector("a.ep-details").getAttribute("href");
        const title = element.querySelector(".ep-origin-name").innerHTML;
        const title_text = title.replace(/\r|\n|\t/g, "")
        const cover = element.querySelector("img").getAttribute("data-src");
        mangas.push({
            title: title_text,
            url,
            cover,
        });
    });
    return mangas;
}
