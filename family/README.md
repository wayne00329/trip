# 行程登入版

登入後才能開啟行程編輯器。第一次登入會從空白開始，編輯的行程會存在目前的瀏覽器。同一組帳密在不同裝置或不同瀏覽器登入時，各自有自己的行程。

正式網址是 [家庭行程](https://family-trip-wayne00329.wayne00329-travel.workers.dev/)。GitHub Pages 首頁會連到 Cloudflare 的登入頁。本機網址上的既有行程會保留在原本的瀏覽器與網址。

## 在 Windows 本機試用

在檔案總管雙擊 `start-family.cmd`，或從 `C:\trip` 開啟 PowerShell，使用 Node.js 24 執行以下指令。

```powershell
node family/server.mjs
```

開啟 `http://127.0.0.1:4173`。首次使用時，直接在網頁設定帳號和至少 12 個字元的密碼，再登入。已設定的帳密可直接使用。

- 要查看或分享 PDF，點「匯出 PDF」，在瀏覽器列印視窗選「另存為 PDF」。
- 若手上有舊版的 JSON 行程備份，可用「匯入備份」開啟。
- 在「旅費管理」新增分帳成員後，「記一筆」可選平均分帳、付款人與分攤成員。每筆的分攤金額與整趟旅程的建議結算都會列出。
- 行前清單會加入基本出國用品，可自行勾選、新增、修改或刪除項目。

## 更新 Cloudflare 上的正式網站

從專案根目錄執行下列指令。Workers 執行登入與編輯頁，SQLite Durable Object 保存登入工作階段並限制登入嘗試。行程資料仍由瀏覽器保存。

```powershell
npx.cmd --yes wrangler@4.164.0 login --device
npx.cmd --yes wrangler@4.164.0 deploy --config family/wrangler.toml
```

首次部署或更換家庭帳密時，先在本機執行 `node family/server.mjs setup` 設定帳密，再將帳號和密碼雜湊透過管線寫入 Cloudflare 的加密秘密設定。

```powershell
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
node family/cloud-account.mjs | npx.cmd --yes wrangler@4.164.0 secret bulk --config family/wrangler.toml
```

## 自行架設 Node.js 主機

將 `family` 資料夾部署到能執行 Node.js 24 且有持久磁碟的主機。透過 HTTPS 反向代理指向 Node.js 服務，將 `TRIP_PUBLIC_ORIGIN` 設為對外的完整網站來源（例如 `https://trip.example.com`），並將 `TRIP_DATA_DIR` 設為持久磁碟上的資料夾。Node.js 預設監聽 `127.0.0.1:4173`。需要從容器網路或其他介面存取時，用 `TRIP_HOST` 和 `PORT` 調整監聽位置。網站需部署在網址的根路徑。

在該主機使用相同的資料目錄執行 `node server.mjs setup`，再以 `node server.mjs` 啟動服務。無互動的部署環境可由主機的秘密設定提供 `TRIP_USERNAME` 和 `TRIP_PASSWORD`，只在執行 `setup` 時使用。把 HTTPS 網址和帳密私下提供給需要編輯的人。重新執行 `setup` 可更換帳密並登出既有工作階段。瀏覽器中的行程依帳號名稱儲存。

登入服務需要上述 Node.js 主機，GitHub Pages 可展示靜態首頁。伺服器的預設資料目錄是 `family/.data/`，用於保存帳密和登入工作階段。行程存於瀏覽器。
