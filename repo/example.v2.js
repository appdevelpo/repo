// ==MiruExtension==
// @name         Example Library(V2)
// @version      v0.0.1
// @author       appdevelpo
// @lang         langcode
// @license      MIT
// @package      example.v2
// @type         bangumi
// @webSite      https://www.example.com
// @nsfw         false
// @apiVersion   2
// ==/MiruExtension==
//

var load = async () => {
}
var latest = async () => {
// https://github.com/WebReflection/linkedom
var {parseHTML} = require("linkedom")
    const {
  // note, these are *not* globals
document, 
  // other exports ..
} = parseHTML(`
  <!doctype html>
  <html lang="en">
    <head>
      <title>Hello SSR</title>
    </head>
    <body>
      <form>
        <input name="user">
        <button>
          Submit
        </button>
      </form>
    </body>
  </html>
`);
    console.log(document.toString());

    // https://cryptojs.gitbook.io/docs
    const {CryptoJS} = require('crypto-js');
    var hash = CryptoJS.SHA256("Message")
    console.log(hash.toString(CryptoJS.enc.Base64))
    console.log(hash.toString(CryptoJS.enc.Hex))
    //L3dmip37+NWEi57rSnFFypTG7ZI25Kdz9tyvpRMrL5E=
    //2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91
    var JsonFormatter = {
  stringify: function(cipherParams) {
    // create json object with ciphertext
    var jsonObj = { ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64) };

    // optionally add iv or salt
    if (cipherParams.iv) {
      jsonObj.iv = cipherParams.iv.toString();
    }

    if (cipherParams.salt) {
      jsonObj.s = cipherParams.salt.toString();
    }

    // stringify json object
    return JSON.stringify(jsonObj);
  },
  parse: function(jsonStr) {
    // parse json string
    var jsonObj = JSON.parse(jsonStr);

    // extract ciphertext from json object, and create cipher params object
    var cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(jsonObj.ct)
    });

    // optionally extract iv or salt

    if (jsonObj.iv) {
      cipherParams.iv = CryptoJS.enc.Hex.parse(jsonObj.iv);
    }

    if (jsonObj.s) {
      cipherParams.salt = CryptoJS.enc.Hex.parse(jsonObj.s);
    }

    return cipherParams;
  }
};
var encrypted_AES = CryptoJS.AES.encrypt("Message", "Secret Passphrase", {
  format: JsonFormatter
});
console.log(encrypted_AES)
// > {
//     ct: "tZ4MsEnfbcDOwqau68aOrQ==",
//     iv: "8a8c8fd8fe33743d3638737ea4a00698",
//     s: "ba06373c8f57179c"
//   };
// ​

var encrypted_AES = CryptoJS.AES.encrypt("Message", "Secret Passphrase");
var decrypted_AES = CryptoJS.AES.decrypt(encrypted_AES, "Secret Passphrase");
console.log(decrypted_AES.toString(CryptoJS.enc.Utf8));
var encrypted_AES = CryptoJS.Rabbit.encrypt("Message", "Secret Passphrase");
var decrypted_AES = CryptoJS.Rabbit.decrypt(encrypted_AES, "Secret Passphrase");
console.log(decrypted_AES.toString(CryptoJS.enc.Utf8));
//Message
//Message

// https://github.com/blueimp/JavaScript-MD5/blob/master/README.md
const {md5} = require("md5")
var hash = md5('value') // "2063c1608d6e0baf80249c42e2be5804"
console.log(hash)

// https://ithelp.ithome.com.tw/m/articles/10381306
const {JSEncrypt} = require('jsencrypt');

const privateKey = `-----BEGIN RSA PRIVATE KEY-----MIIEoQIBAAKCAQBoEVq72+LuWi38uTUDesQxYIuaSq41/pLx1Xh2ax4f7S/f2klABJ+yrz3RoS5MI0AiKQs5J77OxMUITL6lBHbcU9L3fb2MnYq0X/SWlxarMBizxboIvj1aoHZhTHFXsKP8+0q34gyP2iyDEIkdv6N3HLK0wIxRhUoF5/TnJfCllf8weLHkml6TlYOG86EKjTqBpxjhPIx7JfNbIVvGPyZ0s+O6U1DYspSvRduyFkPzanvlB9qV5ZOCtXqF4Y7lxcg5GmaiHFP/p79EKMoJyoO591+dP3cvVU82TVXDp/S5+fFskdl9vTNhUGIGeXxqFOXL0i46nG8LJ/klk7y8UV9bAgMBAAECggEAKm2A33wrTd/IRfPAUFXZ7QOeht4RnoPWpu/QN/89/eg2j34wRQBdl3zoqDGdbX8lo4e2QqwYl7YTWmnng+GJEBTAuxQxlkWYiidg0ZBxtoNaXtirGutsmik3ej2vLAAhK3/MG6H2WyOo6BpyvIUoAOTbWuPxkT7VSgkiiKaoMOmqoPC9+wRv3smVnbDKZC0EmngWxFGhYAh2NyH8ibtxqXwyNBVNRYij2gB7cgzqJ+xHiinXA6w3xvD7kIhOnBJwdSLwwnb6KPnlkdKhJk+MDSYiWvvTNH3PlS6AfgrsAWPyRrWL7RP0Hdth3HWcCvefFVru7zPEH5EDQ4MDV14P0QKBgQC/fSQQv14I7d6oHQ5S+uf6051o6iNyWrElmyo3mvgBb2SDB8myulJrNN4rjWLh3i3RgyEfZG1J0GOu7Ipj/YWfNVUEt98c0IKePvjm/fWFiGm13y/b0MCSx/AcyTWUDjHes2FsTkwcA7+L6esKuELkPI840eTneY5rbrjrWQKxWQKBgQCLIKEbewCnhDlA2N7uwdyGWJh+KveDaH+0aVcBGsUJqsdYzMGnmJWrWFmqnpbZLcUvAEjP7n69xW+xgSO+dDs/45za4iBZ2+S6gQ95VmLeKqJLzqdj8uNguE+e0jsEWmshD2cIgnuvq4XviC/kXc5YeItcZ9abnANmD/AlpqFr0wKBgA1WlS2Jdu5eS1UgeP/0tDX3iY5mSMPNZ2t8LGulIsNO1AyAfV8ytUz8aMFV3t5m0IA4hxUdtLMgjeEAXv9qCGW3nE1w1Vy3dXG6ZzIH3JNJljtx6W6BUvimbqZCqbW/a1/c1NtrdMe6xxvi1llvzlEBmuRVUoGBKRd4pe7Wy2Y5AoGACQoLrZ9mQXwDxETS5yxNSaVD8x6TikQl1/DoKDg3CRPBc/GJu3vcbY+F8+Ht5xpkL1OTZ38VWPsU8LF1QxCGMPZ24HnEpFH3IG72NGn6bnjSpp48ne/P+h6/fZAnKXc+cp1vkkv4AUfhodh1VB8MIw9h7pUIin+ucNkkPy3+WuUCgYBDU4ZbwnEVHNwwfYuf8Ec8PVhQ+Ba7wUtvMBFusj6fEDocnlARM8tVItoz6N1TkaT6jRjEG5+tMiQaFT6Juy0kWUfw3JNflvYD8ZYpS4iYxQmk3nCzTiOJm0S/mOnv0pmLVEafwXRnJ2TQpjbKeEJDd29leBaKaJjPIxgZu9wJwA==-----END RSA PRIVATE KEY-----`

const encrypted = `YzJ/y+2AUqoZzQQNgzNWTQQ4UXwk5KaSrpCN/NL8YWzG8AazB/nabCwYjsZ8oIqPGbM+dK/mifcmOcs5kHyTV0aDmBlhcF/bbnqhIeaZn0+GOT+2Ueykdqyt2U0ACz+l5YWz02sdzSNI/UZHhhf0nCjSPDHAv2qHeStAdWhZenuM2ZhyZRXrVJe6QZEs9eaOiKVHtTk0QczWoiKt/KU03VTabOV5Ky45axYFa4kf4KpWeC9Gsqg2nlt/W4WJ6Ag6AIx+uOI9AnWrKezPNKjCRQ+GH+SHuqF//xniBb4v4m0b07MCSfMyMLS5bbmBVlWvcwEPjeiLHP2Hdn/CPU2EZQ==`;

const encryptor = new JSEncrypt();
encryptor.setPrivateKey(privateKey);
const decrypted = encryptor.decrypt(encrypted);
console.log("解密結果：", decrypted);

}