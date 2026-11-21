const { app, BrowserWindow, shell, Menu } = require('electron');
const path = require('path');
const URL_ = 'https://retro-blocks.onrender.com';
if (!app.requestSingleInstanceLock()) app.quit();
let win, splash;
const SPLASH_MS = 10000;
function create() {
  Menu.setApplicationMenu(null);
  win = new BrowserWindow({ width: 1280, height: 800, minWidth: 900, minHeight: 600, title: 'Retro Blox', backgroundColor: '#111111', autoHideMenuBar: true, show: false, icon: path.join(__dirname, 'build', 'icon.ico'), webPreferences: { contextIsolation: true, nodeIntegration: false } });
  const load = () => win.loadURL(URL_);
  win.webContents.on('did-fail-load', (e, code, desc, url, isMain) => {
    if (!isMain || code === -3) return;
    win.loadFile(path.join(__dirname, 'offline.html'));
    setTimeout(load, 5000);
  });
  win.webContents.setWindowOpenHandler(({ url }) => { if (!url.startsWith(URL_)) { shell.openExternal(url); return { action: 'deny' }; } return { action: 'allow' }; });
  // Splash screen: shown on every launch for 10 seconds while the game loads in the background.
  splash = new BrowserWindow({ width: 520, height: 320, frame: false, resizable: false, movable: true, center: true, alwaysOnTop: true, skipTaskbar: false, title: 'Retro Blox', backgroundColor: '#ffffff', icon: path.join(__dirname, 'build', 'icon.ico'), webPreferences: { contextIsolation: true, nodeIntegration: false } });
  splash.loadFile(path.join(__dirname, 'splash.html'));
  splash.on('closed', () => { splash = null; });
  setTimeout(() => {
    if (win && !win.isDestroyed()) { win.show(); win.focus(); }
    if (splash && !splash.isDestroyed()) splash.close();
  }, SPLASH_MS);
  load();
}
app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
app.whenReady().then(create);
app.on('window-all-closed', () => app.quit());
