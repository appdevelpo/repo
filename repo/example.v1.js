// ==MiruExtension==
// @name         Example Library(V1)
// @version      v0.0.1
// @author       appdevelpo
// @lang         zh-cn
// @license      MIT
// @package      example.v1
// @type         bangumi
// @webSite      https://www.agedm.io/
// @nsfw         false
// ==/MiruExtension==
//

export default class extends Extension {

  async load() {
    this.registerSetting({
      title: "Base URL",
      key: "comicextra",
      type: "input",
      description: "Homepage URL for ComicExtra",
      defaultValue: "https://comixextra.com",
    });
    const d = await this.getSetting("comicextra");
    console.log("getSetting:", d);
    console.log("Example Library(V1) loaded");
  }
  async latest(page) {
    console.log("Latest page:", page);
    return Array.from({ length: 25 }, (_, index) => ({
      title: `Latest ${index}`,
      url: ``,
      cover: `https://picsum.photos/200/300`,
    }));
  }

  async search(keyword, page) {
    console.log("Search keyword:", keyword, "page:", page);
    return Array.from({ length: 20 }, (_, index) => ({
      title: `Search Result ${index} for "${keyword}"`,
      url: ``,
      cover: `https://picsum.photos/200/300`,
    }));
  }
  async detail(url) {
    return {
      title: `Example Title`,
      cover: `https://picsum.photos/200/300`,
      desc: `This is an example description.`,
      episodes: [{
        title: "video1",
        urls: Array.from({ length: 5 }, (_, index) => ({
          name: index.toString(),
          url: "",
        })),
      }],
    };
  }

  async watch(url) {
    return {
      type: "hls",
      url: "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8",
    };
  }
}
