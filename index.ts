import { URLSearchParams } from "url";
import fs from "fs";
import crypto from "crypto";
import path from "path";

let cookie = "";

async function login() {
  const url = "https://challenge.sunvoy.com/login";
  const res = await fetch(url);
  const resp = await res.text();

  const nonce = resp.match(/name="nonce" value="([^"]+)"/);

  if (!nonce) {
    throw new Error("Not found");
  }
  const value = nonce[1];

  const formDate = new URLSearchParams();
  formDate.append("username", "demo@example.org");
  formDate.append("password", "test");
  formDate.append("nonce", value);

  const loginRes = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formDate.toString(),
    redirect: "manual",
  });

  const respCookie = loginRes?.headers?.get("set-cookie");

  if (!respCookie) {
    throw new Error("Not found");
  }
  cookie = respCookie;

  fs.writeFile("session.txt", respCookie.toString(), (err) => {
    if (err) {
      console.log(err);
    }
  });
}

const start = async (usersFetch: () => void, authUser: () => void) => {
  const file = path.join(__dirname, "session.txt");

  fs.readFile(file, "utf8", async (err, data) => {
    if (err?.code === "ENOENT") {
      await login();
    } else {
      cookie = data?.trim();
    }

    setTimeout(() => {
      usersFetch();
    }, 1000);
    setTimeout(() => {
      authUser();
    }, 1600);
  });
};

const getUsersList = async () => {
  const user_url = "https://challenge.sunvoy.com/api/users";

  const res = await fetch(user_url, {
    method: "POST",
    headers: {
      Cookie: cookie,
    },
  });
  if (res.status === 401) {
    await login();
    return getUsersList();
  }
  const response = await res.text();
  const parsed = JSON.parse(response);
  if (response) {
    fs.writeFile("users.json", JSON.stringify(parsed, null, 2), (err) => {
      if (err) {
        console.log(err);
      }
    });
  }
};

const getAuthenticatedUser = async () => {
  const token_url = "https://challenge.sunvoy.com/settings/tokens";
  const settings_url = "https://api.challenge.sunvoy.com/api/settings";
  const file = path.join(__dirname, "users.json");

  const res = await fetch(token_url, {
    method: "GET",
    headers: {
      Cookie: cookie,
    },
  });

  if (res.status === 401) {
    await login();
    return getAuthenticatedUser();
  }

  const response = await res.text();
  const accesstoken = response.match(/id="access_token" value="([^"]+)"/);
  const openId = response.match(/id="openId" value="([^"]+)"/);
  const userId = response.match(/id="userId" value="([^"]+)"/);
  const apiuser = response.match(/id="apiuser" value="([^"]+)"/);
  const operateId = response.match(/id="operateId" value="([^"]+)"/);
  const language = response.match(/id="language" value="([^"]+)"/);

  if (
    !accesstoken ||
    !openId ||
    !userId ||
    !apiuser ||
    !operateId ||
    !language
  ) {
    throw new Error("Not found");
  }

  console.log(
    accesstoken[1],
    openId[1],
    userId[1],
    apiuser[1],
    operateId[1],
    language[1]
  );
  const date = Math.floor(Date.now() / 1e3);

  const n = `access_token=${encodeURIComponent(
    accesstoken[1]
  )}&apiuser=${encodeURIComponent(apiuser[1])}&language=${encodeURIComponent(
    language[1]
  )}&openId=${encodeURIComponent(openId[1])}&operateId=${encodeURIComponent(
    operateId[1]
  )}&timestamp=${encodeURIComponent(
    date.toString()
  )}&userId=${encodeURIComponent(userId[1])}`;

  const hmac = crypto.createHmac("sha1", "mys3cr3t");
  hmac.update(n);
  const digest = hmac.digest("hex").toUpperCase();

  const formData = new URLSearchParams();

  formData.append("access_token", accesstoken[1]);
  formData.append("apiuser", apiuser[1]);
  formData.append("language", language[1]);
  formData.append("openId", openId[1]);
  formData.append("operateId", operateId[1]);
  formData.append("userId", userId[1]);
  formData.append("timestamp", date.toString());
  formData.append("checkcode", digest);

  const settings = await fetch(settings_url, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formData.toString(),
    redirect: "manual",
  });

  const val = await settings.json();
  if (val) {
    fs.readFile(file, "utf8", (err, data) => {
      if (err?.code === "ENOENT") {
        const data = [val];
        const newData = JSON.stringify(data, null, 2);
        fs.writeFile("users.json", newData, (err) => {
          if (err) {
            console.log(err);
          }
        });
      }

      let users = [];
      users = JSON.parse(data);
      if (Array.isArray(users)) {
        users.push(val);
        const updatedData = JSON.stringify(users, null, 2);
        fs.writeFile("users.json", updatedData, (err) => {
          if (err) {
            console.log(err);
          }
        });
      }
    });
  }
};

start(getUsersList, getAuthenticatedUser);
