# 行程登入版

登入後才能開啟行程編輯器。第一次登入會從空白開始，編輯的行程會存在目前的瀏覽器。同一組帳密在不同裝置或不同瀏覽器登入時，各自有自己的行程。

## 在 Windows 本機試用

在檔案總管雙擊 `start-family.cmd`，或從 `C:\trip` 開啟 PowerShell，使用 Node.js 24 執行以下指令。

```powershell
node family/server.mjs
```

開啟 `http://127.0.0.1:4173`。首次使用時，直接在網頁設定帳號和至少 12 個字元的密碼，再登入。已設定的帳密可直接使用。

- 要查看或分享 PDF，點「匯出 PDF」，在瀏覽器列印視窗選「另存為 PDF」。
- 要搬移或備份行程，點「備份 JSON」，再到新裝置點「匯入備份」並選擇該檔案。

## 讓其他地方的家人使用

將 `family` 資料夾部署到能執行 Node.js 24 且有持久磁碟的主機。透過 HTTPS 反向代理指向 Node.js 服務，將 `TRIP_PUBLIC_ORIGIN` 設為對外的完整網站來源（例如 `https://trip.example.com`），並將 `TRIP_DATA_DIR` 設為持久磁碟上的資料夾。Node.js 預設監聽 `127.0.0.1:4173`。需要從容器網路或其他介面存取時，用 `TRIP_HOST` 和 `PORT` 調整監聽位置。網站需部署在網址的根路徑。

在該主機使用相同的資料目錄執行 `node server.mjs setup`，再以 `node server.mjs` 啟動服務。無互動的部署環境可由主機的秘密設定提供 `TRIP_USERNAME` 和 `TRIP_PASSWORD`，只在執行 `setup` 時使用。把 HTTPS 網址和帳密私下提供給需要編輯的人。重新執行 `setup` 可更換帳密並登出既有工作階段。如果更換帳號名稱，請先匯出行程，再用新帳號登入匯入。

登入服務需要上述 Node.js 主機，GitHub Pages 可展示靜態首頁。伺服器的預設資料目錄是 `family/.data/`，用於保存帳密和登入工作階段。行程存於瀏覽器，可用「備份 JSON」留存。
