package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	baseDir    string
	dirMu      sync.Mutex
	username   string
	password   string
	tokens     map[string]time.Time
	tokenMu    sync.RWMutex
	tlsEnabled bool
	certFile   string
	keyFile    string
)

// TokenInfo 存储token信息
type TokenInfo struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Breadcrumb 用于生成面包屑导航数据
type Breadcrumb struct {
	Name string
	Path string
}

// FileInfo 存储文件或目录的基本信息，RawSize 与 ModTime 用于排序
type FileInfo struct {
	Name       string
	Size       string
	RawSize    int64
	UploadDate string
	ModTime    time.Time
	IsDir      bool
}

// PageData 用于传递给模板的数据，新增加 Order 字段用于记录排序顺序
type PageData struct {
	Files       []FileInfo
	Breadcrumbs []Breadcrumb // 面包屑导航数据
	CurrentPath string       // 当前目录（相对于 baseDir）
	Sort        string       // 当前排序字段："name"、"time"、"size"
	Order       string       // 排序顺序："asc" 或 "desc"
	Username    string       // 当前登录用户名
}

// loginTemplate 登录页面模板
const loginTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-container {
      background: white;
      padding: 40px;
      border-radius: 10px;
      box-shadow: 0 15px 35px rgba(0,0,0,0.1);
      width: 100%;
      max-width: 400px;
    }
    .login-title {
      text-align: center;
      margin-bottom: 30px;
      color: #333;
      font-size: 24px;
    }
    .form-group {
      margin-bottom: 20px;
    }
    .form-group label {
      display: block;
      margin-bottom: 5px;
      color: #555;
      font-weight: bold;
    }
    .form-group input {
      width: 100%;
      padding: 12px;
      border: 2px solid #ddd;
      border-radius: 5px;
      font-size: 16px;
      transition: border-color 0.3s;
      box-sizing: border-box;
    }
    .form-group input:focus {
      outline: none;
      border-color: #667eea;
    }
    .login-btn {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 5px;
      font-size: 16px;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .login-btn:hover {
      transform: translateY(-2px);
    }
    .error-msg {
      color: #e74c3c;
      text-align: center;
      margin-top: 15px;
      display: none;
    }
    .remember-me {
      display: flex;
      align-items: center;
      margin-bottom: 20px;
    }
    .remember-me input {
      margin-right: 8px;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h2 class="login-title">简易网页文件管理器</h2>
    <form id="loginForm">
      <div class="form-group">
        <label for="username">用户名:</label>
        <input type="text" id="username" name="username" required>
      </div>
      <div class="form-group">
        <label for="password">密码:</label>
        <input type="password" id="password" name="password" required>
      </div>
      <div class="remember-me">
        <input type="checkbox" id="rememberMe" name="rememberMe" checked>
        <label for="rememberMe">记住登录状态 (30天)</label>
      </div>
      <button type="submit" class="login-btn">登录</button>
      <div id="errorMsg" class="error-msg"></div>
    </form>
  </div>

  <script>
    document.getElementById('loginForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const rememberMe = document.getElementById('rememberMe').checked;
      const errorMsg = document.getElementById('errorMsg');
      
      try {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            username: username,
            password: password,
            remember_me: rememberMe
          })
        });
        
        const data = await response.json();
        
        if (response.ok) {
          // 设置cookie
          const expires = rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000; // 30天或1天
          document.cookie = 'auth_token=' + data.token + '; expires=' + new Date(Date.now() + expires).toUTCString() + '; path=/';
          
          // 跳转到主页
          window.location.href = '/';
        } else {
          errorMsg.textContent = data.error || '登录失败';
          errorMsg.style.display = 'block';
        }
      } catch (error) {
        errorMsg.textContent = '网络错误，请重试';
        errorMsg.style.display = 'block';
      }
    });
  </script>
</body>
</html>
`

// combinedTemplate 同时定义整个页面模板（"main"）和仅文件列表部分模板（"fileList"）
const combinedTemplate = `
{{define "main"}}
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>简易网页文件管理器</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background-color: #f5f5f5;
    }
    .container {
      max-width: 900px;
      margin: 20px auto;
      padding: 10px;
      background-color: #fff;
      border-radius: 5px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    h1 {
      text-align: center;
      color: #333;
    }
    .breadcrumbs {
      margin: 10px 0;
      font-size: 14px;
    }
    .breadcrumbs a {
      text-decoration: none;
      color: #007bff;
      margin-right: 5px;
    }
    .breadcrumbs span {
      margin-right: 5px;
    }
    .nav-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: space-between;
      align-items: center;
      margin: 10px 0;
    }
    .nav-actions .action-group {
      flex: 1 1 auto;
      display: flex;
      gap: 10px;
      align-items: center;
    }
    .progress-bar {
      width: 100%;
      height: 20px;
      background-color: #e9ecef;
      border-radius: 3px;
      overflow: hidden;
      display: none;
      margin: 10px 0;
    }
    .progress {
      height: 100%;
      background-color: #007bff;
      text-align: center;
      color: #fff;
      line-height: 20px;
    }
    .btn {
      padding: 5px 10px;
      border: none;
      border-radius: 3px;
      text-decoration: none;
      color: #fff;
      cursor: pointer;
      margin-top: 5px;
      white-space: nowrap;
    }
    .btn-upload {
      background-color: #007bff;
    }
    .btn-create-file {
      background-color: #28a745;
    }
    .btn-create-folder {
      background-color: #fd7e14;
    }
    .btn-refresh {
      background-color: #28a745;
    }
    .btn-enter {
      background-color: #2196F3;
    }
    .btn-download {
      background-color: #2196F3;
    }
    .btn-delete {
      background-color: #E53935;
    }
    .btn-rename {
      background-color: #FF9800;
    }
    .btn-cancel {
      background-color: #28a745;
    }
    .file-name {
      max-width: 200px;
      white-space: normal;
      word-break: break-all;
      cursor: pointer;
    }
    .file-name.directory {
      color: #007bff;
      font-weight: bold;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      table-layout: auto;
    }
    th, td {
      padding: 8px;
      border: 1px solid #ddd;
      text-align: left;
    }
    th {
      background-color: #f2f2f2;
      position: relative;
    }
    th a {
      text-decoration: none;
      color: inherit;
      display: block;
    }
    table th:nth-child(2), table td:nth-child(2) {
      width: 100px;
      word-break: break-word;
    }
    table th:nth-child(3), table td:nth-child(3) {
      width: 80px;
      white-space: nowrap;
    }
    #searchInput {
      width: 100%;
      padding: 5px;
      margin-bottom: 10px;
      box-sizing: border-box;
    }
    @media only screen and (max-width: 600px) {
      .container {
        width: 95%;
      }
      table, th, td {
        font-size: 14px;
      }
      .nav-actions {
        flex-direction: column;
      }
      .nav-actions .action-group {
        width: 100%;
        flex-direction: row;
        justify-content: space-between;
      }
      .file-name {
        max-width: 100%;
      }
    }
    .modal {
      display: none; 
      position: fixed; 
      z-index: 999;
      padding-top: 100px; 
      left: 0;
      top: 0;
      width: 100%; 
      height: 100%; 
      overflow: auto; 
      background-color: rgba(0,0,0,0.4);
    }
    .modal-content {
      background-color: #fff;
      margin: auto;
      padding: 20px;
      border-radius: 5px;
      max-width: 90%;
      width: 400px;
      position: relative;
    }
    .close {
      color: #aaa;
      position: absolute;
      top: 10px;
      right: 20px;
      font-size: 28px;
      font-weight: bold;
      cursor: pointer;
    }
    .close:hover,
    .close:focus {
      color: #000;
    }
    .modal-content input[type="text"] {
      width: 100%;
      padding: 5px;
      margin: 10px 0;
      border: 1px solid #ccc;
      border-radius: 3px;
    }
    .modal-buttons {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: center;
      margin-top: 15px;
    }
    .modal-buttons button {
      flex: 1 1 30%;
      padding: 10px;
      border: none;
      border-radius: 3px;
      cursor: pointer;
      min-width: 80px;
      color: #fff;
    }
    .modal-actions {
      text-align: center;
      margin-top: 10px;
    }
    .modal-actions .btn {
      padding: 10px 20px;
    }
  </style>
  <script>
    if (/Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent)) {
      document.documentElement.classList.add('mobile');
    }
  </script>
</head>
<body>
<div class="container">
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
    <h1 style="margin: 0;">简易网页文件管理器</h1>
    {{if ne .Username ""}}
    <button onclick="logout()" style="padding: 8px 16px; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px;">退出登录</button>
    {{end}}
  </div>
  <div class="breadcrumbs">
    {{range $index, $crumb := .Breadcrumbs}}
      {{if eq $index 0}}
        <a href="/?path={{$crumb.Path}}{{if $.Sort}}&sort={{$.Sort}}{{end}}{{if $.Order}}&order={{$.Order}}{{end}}">{{$crumb.Name}}</a>
      {{else}}
        <span>&gt;</span>
        {{if eq $index (sub (len $.Breadcrumbs) 1)}}
          <span>{{$crumb.Name}}</span>
        {{else}}
          <a href="/?path={{$crumb.Path}}{{if $.Sort}}&sort={{$.Sort}}{{end}}{{if $.Order}}&order={{$.Order}}{{end}}">{{$crumb.Name}}</a>
        {{end}}
      {{end}}
    {{end}}
  </div>

  <div>
    <input type="text" id="searchInput" placeholder="查找文件（输入名称筛选）" onkeyup="filterFiles()">
  </div>

  <div class="nav-actions">
    <div class="action-group">
      <input type="file" id="fileInput" multiple>
      <button class="btn btn-upload" onclick="uploadFile()">上传文件</button>
    </div>
    <div class="action-group">
      <button class="btn btn-create-file" onclick="showModal('modalCreateFile')">创建文件</button>
      <button class="btn btn-create-folder" onclick="showModal('modalCreateFolder')">创建文件夹</button>
      <button class="btn btn-refresh" onclick="refreshFileList()">刷新</button>
    </div>
  </div>
  
  <div class="progress-bar" id="progressContainer">
    <div class="progress" id="progressBar" style="width: 0;">0%</div>
  </div>
  
  <div id="fileListContainer">
    {{template "fileList" .}}
  </div>
</div>

<div id="modalCreateFile" class="modal">
  <div class="modal-content">
    <span class="close" onclick="closeModal('modalCreateFile')">&times;</span>
    <h2>创建文件</h2>
    <input type="text" id="modalFileName" placeholder="请输入文件名">
    <button class="btn btn-create-file" onclick="submitCreateFile()">确定</button>
    <button class="btn btn-cancel" onclick="closeModal('modalCreateFile')">取消</button>
  </div>
</div>

<div id="modalCreateFolder" class="modal">
  <div class="modal-content">
    <span class="close" onclick="closeModal('modalCreateFolder')">&times;</span>
    <h2>创建文件夹</h2>
    <input type="text" id="modalFolderName" placeholder="请输入文件夹名">
    <button class="btn btn-create-folder" onclick="submitCreateFolder()">确定</button>
    <button class="btn btn-cancel" onclick="closeModal('modalCreateFolder')">取消</button>
  </div>
</div>

<div id="modalFileOptions" class="modal">
  <div class="modal-content">
    <span class="close" onclick="closeModal('modalFileOptions')">&times;</span>
    <h2 id="modalTitle"></h2>
    <div id="modalButtons" class="modal-buttons"></div>
    <div class="modal-actions">
      <button class="btn btn-cancel" onclick="closeModal('modalFileOptions')">取消</button>
    </div>
  </div>
</div>

<script>
  function sub(a, b) { return a - b; }

  var currentPath = "{{.CurrentPath}}";
  var urlParams = new URLSearchParams(window.location.search);
  var currentSort = urlParams.get("sort") || "name";
  var currentOrder = urlParams.get("order") || (currentSort == "time" ? "desc" : "asc");

  function uploadFile() {
    var fileInput = document.getElementById('fileInput');
    var files = fileInput.files;
    if (files.length === 0) {
      alert('请选择至少一个文件');
      return;
    }
    var formData = new FormData();
    for (var i = 0; i < files.length; i++) {
      formData.append('files[]', files[i]);
    }
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/upload?path=' + encodeURIComponent(currentPath), true);
    var progressBar = document.getElementById('progressBar');
    var progressContainer = document.getElementById('progressContainer');
    progressBar.style.width = '0';
    progressBar.innerText = '0%';
    progressContainer.style.display = 'block';
    xhr.upload.onprogress = function (event) {
      if (event.lengthComputable) {
        var percentComplete = Math.round((event.loaded / event.total) * 100);
        progressBar.style.width = percentComplete + '%';
        progressBar.innerText = percentComplete + '%';
      }
    };
    xhr.onload = function () {
      progressContainer.style.display = 'none';
      if (xhr.status === 200) {
        alert('文件上传成功');
        refreshFileList();
      } else {
        alert('文件上传失败');
      }
    };
    xhr.send(formData);
  }

  function refreshFileList() {
    var yOffset = window.pageYOffset;
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/list?path=' + encodeURIComponent(currentPath) + '&sort=' + encodeURIComponent(currentSort) + '&order=' + encodeURIComponent(currentOrder), true);
    xhr.onload = function () {
      if (xhr.status === 200) {
        document.getElementById("fileListContainer").innerHTML = xhr.responseText;
        window.scrollTo(0, yOffset);
      } else {
        alert('刷新文件列表失败');
      }
    };
    xhr.send();
  }

  function showModal(modalId) {
    document.getElementById(modalId).style.display = "block";
  }
  
  function closeModal(modalId) {
    document.getElementById(modalId).style.display = "none";
  }

  function submitCreateFile() {
    var fileName = document.getElementById('modalFileName').value.trim();
    if (!fileName) {
      alert('请输入文件名');
      return;
    }
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/create', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function () {
      if (xhr.status === 200) {
        alert('文件创建成功');
        closeModal('modalCreateFile');
        refreshFileList();
      } else {
        alert('文件创建失败: ' + xhr.responseText);
      }
    };
    xhr.send('type=file&name=' + encodeURIComponent(fileName) + '&path=' + encodeURIComponent(currentPath));
  }

  function submitCreateFolder() {
    var folderName = document.getElementById('modalFolderName').value.trim();
    if (!folderName) {
      alert('请输入文件夹名');
      return;
    }
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/create', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function () {
      if (xhr.status === 200) {
        alert('文件夹创建成功');
        closeModal('modalCreateFolder');
        refreshFileList();
      } else {
        alert('文件夹创建失败: ' + xhr.responseText);
      }
    };
    xhr.send('type=folder&name=' + encodeURIComponent(folderName) + '&path=' + encodeURIComponent(currentPath));
  }

  function renameFile(oldName) {
    var newName = prompt("请输入新的名称", oldName);
    if (!newName || newName === oldName) return;
    closeModal('modalFileOptions');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/rename', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function () {
      if (xhr.status === 200) {
        alert('重命名成功');
        refreshFileList();
      } else {
        alert('重命名失败: ' + xhr.responseText);
      }
    };
    xhr.send('old=' + encodeURIComponent(oldName) + '&new=' + encodeURIComponent(newName) + '&path=' + encodeURIComponent(currentPath));
  }

  function downloadFile(fileName, path, element) {
    closeModal('modalFileOptions');
    var url = '/download?file=' + encodeURIComponent(fileName) + '&path=' + encodeURIComponent(path);
    var link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  function deleteFile(fileName, path, element) {
    if (!confirm("确定要删除 " + fileName + " 吗？")) return;
    closeModal('modalFileOptions');
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/delete?file=' + encodeURIComponent(fileName) + '&path=' + encodeURIComponent(path), true);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    xhr.onload = function () {
      if (xhr.status === 200) {
        alert('删除成功');
        refreshFileList();
      } else {
        alert('删除失败: ' + xhr.responseText);
      }
    };
    xhr.send();
  }

  // 保留showFileOptions函数以防某些地方还在使用，但现在主要使用双击和右键菜单
  function showFileOptions(fileName, isDir) {
    // 直接执行默认操作：目录进入，文件下载
    if (isDir) {
      enterDirectory(fileName);
    } else {
      downloadFile(fileName, currentPath, null);
    }
  }

  function enterDirectory(fileName) {
    closeModal('modalFileOptions');
    var newPath = currentPath ? currentPath + '/' + fileName : fileName;
    window.location.href = '/?path=' + encodeURIComponent(newPath) + '&sort=' + encodeURIComponent(currentSort) + '&order=' + encodeURIComponent(currentOrder);
  }

  var contextFileName = "";
  var contextIsDir = false;
  var touchTimer = null;
  var touchStartTime = 0;

  // 点击其他地方隐藏右键菜单
  document.addEventListener('click', function() {
    var contextMenu = document.getElementById('contextMenu');
    if (contextMenu) {
      contextMenu.style.display = 'none';
    }
  });

  // 阻止默认右键菜单，允许自定义右键菜单
  document.addEventListener('contextmenu', function(e) {
    // 如果是在文件名上右键，阻止默认菜单以显示自定义菜单
    if (e.target.closest('.file-name')) {
      e.preventDefault();
    }
    // 其他地方也阻止默认右键菜单，保持界面一致性
    else {
      e.preventDefault();
    }
  });

  // 移动端长按支持
  function handleTouchStart(event, fileName, isDir) {
    touchStartTime = Date.now();
    touchTimer = setTimeout(function() {
      // 长按500ms后显示菜单
      event.preventDefault();
      showContextMenu(event, fileName, isDir);
    }, 500);
  }

  function handleTouchEnd(event) {
    if (touchTimer) {
      clearTimeout(touchTimer);
      touchTimer = null;
    }
    // 如果是短按（小于500ms），不阻止默认的click事件
    if (Date.now() - touchStartTime < 500) {
      // 短按，让click事件正常执行
      return;
    } else {
      // 长按，阻止click事件
      event.preventDefault();
    }
  }

  function showContextMenu(event, fileName, isDir) {
    event.preventDefault();
    contextFileName = fileName;
    contextIsDir = isDir;
    
    // 创建右键菜单（如果不存在）
    var contextMenu = document.getElementById('contextMenu');
    if (!contextMenu) {
      contextMenu = document.createElement('div');
      contextMenu.id = 'contextMenu';
      contextMenu.style.cssText = 'position: fixed; background: white; border: 1px solid #ccc; border-radius: 4px; padding: 5px 0; box-shadow: 2px 2px 10px rgba(0,0,0,0.3); z-index: 9999; display: none; min-width: 120px;';
      document.body.appendChild(contextMenu);
    }
    
    // 清空菜单内容
    contextMenu.innerHTML = '';
    
    // 添加菜单项（移除进入和下载选项）
    addMenuItem(contextMenu, '重命名', function() {
      renameFile(fileName);
      contextMenu.style.display = 'none';
    }, '#2196F3'); // 蓝色
    
    addMenuItem(contextMenu, '删除', function() {
      deleteFile(fileName, currentPath, null);
      contextMenu.style.display = 'none';
    }, '#e74c3c'); // 红色
    
    // 显示菜单
    contextMenu.style.display = 'block';
    
    // 获取菜单尺寸
    var rect = contextMenu.getBoundingClientRect();
    var menuWidth = rect.width;
    var menuHeight = rect.height;
    
    // 计算最佳位置
    var x = event.clientX;
    var y = event.clientY;
    
    // 确保菜单不超出屏幕右边
    if (x + menuWidth > window.innerWidth) {
      x = window.innerWidth - menuWidth - 10;
    }
    
    // 确保菜单不超出屏幕底部
    if (y + menuHeight > window.innerHeight) {
      y = window.innerHeight - menuHeight - 10;
    }
    
    // 确保菜单不超出屏幕左边和顶部
    if (x < 10) x = 10;
    if (y < 10) y = 10;
    
    contextMenu.style.left = x + 'px';
    contextMenu.style.top = y + 'px';
  }
  
  function addMenuItem(menu, text, onclick, color) {
    var item = document.createElement('div');
    item.textContent = text;
    item.style.cssText = 'padding: 8px 15px; cursor: pointer; border-bottom: 1px solid #eee; color: ' + (color || '#333') + ';';
    item.onmouseover = function() {
      if (color === '#e74c3c') {
        this.style.backgroundColor = '#ffebee';
      } else if (color === '#2196F3') {
        this.style.backgroundColor = '#e3f2fd';
      } else {
        this.style.backgroundColor = '#f0f0f0';
      }
    };
    item.onmouseout = function() {
      this.style.backgroundColor = 'white';
    };
    item.onclick = onclick;
    menu.appendChild(item);
  }

  function filterFiles() {
    var input = document.getElementById("searchInput");
    var filter = input.value.toLowerCase();
    var rows = document.querySelectorAll("#fileListContainer tbody tr");
    rows.forEach(function (row) {
      var cellText = row.cells[0].innerText.toLowerCase();
      row.style.display = cellText.indexOf(filter) > -1 ? "" : "none";
    });
  }

  function logout() {
    // 清除cookie
    document.cookie = 'auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/';
    // 跳转到登出页面
    window.location.href = '/logout';
  }
</script>
</body>
</html>
{{end}}

{{define "fileList"}}
<table>
  <thead>
    <tr>
      <th>
        <a href="/?path={{.CurrentPath}}&sort=name&order={{toggle .Sort .Order "name"}}">
          名称
        </a>
      </th>
      <th>
        <a href="/?path={{.CurrentPath}}&sort=time&order={{toggle .Sort .Order "time"}}">
          最后修改
        </a>
      </th>
      <th>
        <a href="/?path={{.CurrentPath}}&sort=size&order={{toggle .Sort .Order "size"}}">
          大小
        </a>
      </th>
    </tr>
  </thead>
  <tbody>
  {{range .Files}}
    <tr>
      <td class="file-name {{if .IsDir}}directory{{end}}" 
          onclick="{{if .IsDir}}enterDirectory('{{.Name}}'){{else}}downloadFile('{{.Name}}', currentPath, null){{end}}" 
          oncontextmenu="showContextMenu(event, '{{.Name}}', {{.IsDir}})" 
          ontouchstart="handleTouchStart(event, '{{.Name}}', {{.IsDir}})" 
          ontouchend="handleTouchEnd(event)" 
          title="{{.Name}}">
        {{.Name}}
      </td>
      <td>
        {{with $parts := split .UploadDate " "}}
          {{index $parts 0}}<br>{{index $parts 1}}
        {{end}}
      </td>
      <td>{{.Size}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
{{end}}
`

// secureJoin 将 base 与传入的相对路径组合，确保最终路径在 base 内
func secureJoin(base, rel string) (string, error) {
	cleanRel := filepath.Clean(rel)
	full := filepath.Join(base, cleanRel)
	relPath, err := filepath.Rel(base, full)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(relPath, "..") {
		return "", fmt.Errorf("非法路径")
	}
	return full, nil
}

// generateSelfSignedCert 生成自签名证书
func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	// 生成私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"File Manager"},
			Country:       []string{"CN"},
			Province:      []string{"Beijing"},
			Locality:      []string{"Beijing"},
			StreetAddress: []string{"Self-Signed"},
			PostalCode:    []string{"100000"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// 编码证书为PEM格式
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 编码私钥为PEM格式
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	return certPEM, keyPEM, nil
}

// generateToken 生成随机token
func generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}

// isValidToken 检查token是否有效
func isValidToken(token string) bool {
	tokenMu.RLock()
	defer tokenMu.RUnlock()

	expireTime, exists := tokens[token]
	if !exists {
		return false
	}

	// 检查是否过期
	if time.Now().After(expireTime) {
		// 异步清理过期token
		go func() {
			tokenMu.Lock()
			delete(tokens, token)
			tokenMu.Unlock()
		}()
		return false
	}

	return true
}

// addToken 添加新token
func addToken(token string, duration time.Duration) {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	if tokens == nil {
		tokens = make(map[string]time.Time)
	}

	tokens[token] = time.Now().Add(duration)
}

// authHandler 基于token的认证中间件
func authHandler(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 如果没有设置用户名密码，直接通过
		if username == "" || password == "" {
			next.ServeHTTP(w, r)
			return
		}

		// 检查cookie中的token
		cookie, err := r.Cookie("auth_token")
		if err == nil && isValidToken(cookie.Value) {
			next.ServeHTTP(w, r)
			return
		}

		// 检查Authorization header中的token
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			if isValidToken(token) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 未认证，重定向到登录页面
		if r.URL.Path != "/login" && r.URL.Path != "/api/login" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// indexHandler 根据 URL 参数 path 与 sort/order 读取当前目录内容，生成完整页面
func indexHandler(w http.ResponseWriter, r *http.Request) {
	relDir := r.URL.Query().Get("path")
	sortType := r.URL.Query().Get("sort")
	if sortType != "time" && sortType != "size" {
		sortType = "name"
	}
	order := r.URL.Query().Get("order")
	if order != "asc" && order != "desc" {
		if sortType == "time" {
			order = "desc"
		} else {
			order = "asc"
		}
	}

	currentDir, err := secureJoin(baseDir, relDir)
	if err != nil {
		http.Error(w, "无效的目录", http.StatusBadRequest)
		return
	}

	dirMu.Lock()
	entries, err := os.ReadDir(currentDir)
	dirMu.Unlock()
	if err != nil {
		http.Error(w, "无法读取目录", http.StatusInternalServerError)
		return
	}

	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		sizeStr := ""
		rawSize := int64(0)
		if !entry.IsDir() {
			rawSize = info.Size()
			sizeStr = calculateFileSize(rawSize)
		}
		files = append(files, FileInfo{
			Name:       entry.Name(),
			Size:       sizeStr,
			RawSize:    rawSize,
			UploadDate: info.ModTime().Format("2006-01-02 15:04:05"),
			ModTime:    info.ModTime(),
			IsDir:      entry.IsDir(),
		})
	}

	switch sortType {
	case "name":
		if order == "asc" {
			sort.Slice(files, func(i, j int) bool {
				return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
			})
		} else {
			sort.Slice(files, func(i, j int) bool {
				return strings.ToLower(files[i].Name) > strings.ToLower(files[j].Name)
			})
		}
	case "time":
		if order == "asc" {
			sort.Slice(files, func(i, j int) bool {
				return files[i].ModTime.Before(files[j].ModTime)
			})
		} else {
			sort.Slice(files, func(i, j int) bool {
				return files[i].ModTime.After(files[j].ModTime)
			})
		}
	case "size":
		if order == "asc" {
			sort.Slice(files, func(i, j int) bool {
				return files[i].RawSize < files[j].RawSize
			})
		} else {
			sort.Slice(files, func(i, j int) bool {
				return files[i].RawSize > files[j].RawSize
			})
		}
	}

	breadcrumbs := []Breadcrumb{{Name: "根目录", Path: ""}}
	if relDir != "" {
		parts := strings.Split(relDir, "/")
		var cumulative string
		for _, part := range parts {
			if part == "" {
				continue
			}
			if cumulative == "" {
				cumulative = part
			} else {
				cumulative = cumulative + "/" + part
			}
			breadcrumbs = append(breadcrumbs, Breadcrumb{
				Name: part,
				Path: cumulative,
			})
		}
	}

	data := PageData{
		Files:       files,
		Breadcrumbs: breadcrumbs,
		CurrentPath: relDir,
		Sort:        sortType,
		Order:       order,
		Username:    username,
	}

	funcMap := template.FuncMap{
		"sub": func(a, b int) int { return a - b },
		"split": func(s, sep string) []string {
			return strings.Split(s, sep)
		},
		"toggle": func(currentSort, currentOrder, target string) string {
			if currentSort == target {
				if currentOrder == "asc" {
					return "desc"
				}
				return "asc"
			}
			return "asc"
		},
	}

	tmpl := template.Must(template.New("main").Funcs(funcMap).Parse(combinedTemplate))
	tmpl.Execute(w, data)
	runtime.GC()
}

// listHandler 返回仅文件列表部分（用于 AJAX 局部刷新）
func listHandler(w http.ResponseWriter, r *http.Request) {
	relDir := r.URL.Query().Get("path")
	sortType := r.URL.Query().Get("sort")
	if sortType != "time" && sortType != "size" {
		sortType = "name"
	}
	order := r.URL.Query().Get("order")
	if order != "asc" && order != "desc" {
		if sortType == "time" {
			order = "desc"
		} else {
			order = "asc"
		}
	}
	currentDir, err := secureJoin(baseDir, relDir)
	if err != nil {
		http.Error(w, "无效的目录", http.StatusBadRequest)
		return
	}

	dirMu.Lock()
	entries, err := os.ReadDir(currentDir)
	dirMu.Unlock()
	if err != nil {
		http.Error(w, "无法读取目录", http.StatusInternalServerError)
		return
	}

	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		sizeStr := ""
		rawSize := int64(0)
		if !entry.IsDir() {
			rawSize = info.Size()
			sizeStr = calculateFileSize(rawSize)
		}
		files = append(files, FileInfo{
			Name:       entry.Name(),
			Size:       sizeStr,
			RawSize:    rawSize,
			UploadDate: info.ModTime().Format("2006-01-02 15:04:05"),
			ModTime:    info.ModTime(),
			IsDir:      entry.IsDir(),
		})
	}

	switch sortType {
	case "name":
		if order == "asc" {
			sort.Slice(files, func(i, j int) bool {
				return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
			})
		} else {
			sort.Slice(files, func(i, j int) bool {
				return strings.ToLower(files[i].Name) > strings.ToLower(files[j].Name)
			})
		}
	case "time":
		if order == "asc" {
			sort.Slice(files, func(i, j int) bool {
				return files[i].ModTime.Before(files[j].ModTime)
			})
		} else {
			sort.Slice(files, func(i, j int) bool {
				return files[i].ModTime.After(files[j].ModTime)
			})
		}
	case "size":
		if order == "asc" {
			sort.Slice(files, func(i, j int) bool {
				return files[i].RawSize < files[j].RawSize
			})
		} else {
			sort.Slice(files, func(i, j int) bool {
				return files[i].RawSize > files[j].RawSize
			})
		}
	}

	breadcrumbs := []Breadcrumb{{Name: "根目录", Path: ""}}
	if relDir != "" {
		parts := strings.Split(relDir, "/")
		var cumulative string
		for _, part := range parts {
			if part == "" {
				continue
			}
			if cumulative == "" {
				cumulative = part
			} else {
				cumulative = cumulative + "/" + part
			}
			breadcrumbs = append(breadcrumbs, Breadcrumb{
				Name: part,
				Path: cumulative,
			})
		}
	}

	data := PageData{
		Files:       files,
		Breadcrumbs: breadcrumbs,
		CurrentPath: relDir,
		Sort:        sortType,
		Order:       order,
	}

	funcMap := template.FuncMap{
		"sub": func(a, b int) int { return a - b },
		"split": func(s, sep string) []string {
			return strings.Split(s, sep)
		},
		"toggle": func(currentSort, currentOrder, target string) string {
			if currentSort == target {
				if currentOrder == "asc" {
					return "desc"
				}
				return "asc"
			}
			return "asc"
		},
	}

	tmpl := template.Must(template.New("main").Funcs(funcMap).Parse(combinedTemplate))
	tmpl.ExecuteTemplate(w, "fileList", data)
	runtime.GC()
}

// fileUploadHandler 保存上传的文件到指定目录
func fileUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST方法", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	relDir := r.URL.Query().Get("path")
	targetDir, err := secureJoin(baseDir, relDir)
	if err != nil {
		http.Error(w, "无效的路径", http.StatusBadRequest)
		return
	}
	filesUploaded := r.MultipartForm.File["files[]"]
	dirMu.Lock()
	defer dirMu.Unlock()
	for _, fileHeader := range filesUploaded {
		file, err := fileHeader.Open()
		if err != nil {
			http.Error(w, "无法打开文件", http.StatusBadRequest)
			return
		}
		defer file.Close()
		targetPath, err := secureJoin(targetDir, fileHeader.Filename)
		if err != nil {
			http.Error(w, "非法文件名", http.StatusBadRequest)
			return
		}
		out, err := os.Create(targetPath)
		if err != nil {
			http.Error(w, "无法创建文件", http.StatusInternalServerError)
			return
		}
		_, err = io.Copy(out, file)
		out.Close()
		if err != nil {
			http.Error(w, "无法保存文件", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "文件上传成功")
}

// fileDownloadHandler 处理文件下载请求，支持断点续传和多线程下载
func fileDownloadHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	relDir := r.URL.Query().Get("path")
	if fileName == "" {
		http.Error(w, "未指定文件", http.StatusBadRequest)
		return
	}
	targetDir, err := secureJoin(baseDir, relDir)
	if err != nil {
		http.Error(w, "无效的路径", http.StatusBadRequest)
		return
	}
	targetPath, err := secureJoin(targetDir, fileName)
	if err != nil {
		http.Error(w, "无效的文件名", http.StatusBadRequest)
		return
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		http.Error(w, "文件不存在", http.StatusNotFound)
		return
	}
	if info.IsDir() {
		http.Error(w, "无法下载文件夹", http.StatusBadRequest)
		return
	}

	f, err := os.Open(targetPath)
	if err != nil {
		http.Error(w, "无法打开文件", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	fileSize := info.Size()

	// 设置支持断点续传的响应头
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+info.Name()+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")

	// 检查是否有Range请求头（断点续传）
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		// 完整文件下载
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		w.WriteHeader(http.StatusOK)
		io.Copy(w, f)
		return
	}

	// 解析Range请求头
	ranges, err := parseRange(rangeHeader, fileSize)
	if err != nil {
		http.Error(w, "无效的Range请求", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// 目前只支持单个范围请求（多线程下载时客户端会发送多个单范围请求）
	if len(ranges) != 1 {
		http.Error(w, "不支持多范围请求", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	start := ranges[0].start
	end := ranges[0].end
	contentLength := end - start + 1

	// 设置部分内容响应头
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
	w.WriteHeader(http.StatusPartialContent)

	// 定位到指定位置并传输指定范围的数据
	_, err = f.Seek(start, 0)
	if err != nil {
		http.Error(w, "文件定位失败", http.StatusInternalServerError)
		return
	}

	// 限制读取长度
	limitedReader := io.LimitReader(f, contentLength)
	io.Copy(w, limitedReader)
}

// Range表示一个字节范围
type Range struct {
	start, end int64
}

// parseRange 解析HTTP Range头
func parseRange(rangeHeader string, fileSize int64) ([]Range, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("无效的Range格式")
	}

	rangeSpec := rangeHeader[6:] // 去掉"bytes="前缀
	ranges := []Range{}

	// 分割多个范围（用逗号分隔）
	for _, rangeStr := range strings.Split(rangeSpec, ",") {
		rangeStr = strings.TrimSpace(rangeStr)
		if rangeStr == "" {
			continue
		}

		var start, end int64
		var err error

		if strings.Contains(rangeStr, "-") {
			parts := strings.SplitN(rangeStr, "-", 2)
			startStr, endStr := parts[0], parts[1]

			if startStr == "" {
				// 后缀范围：-500 表示最后500字节
				if endStr == "" {
					return nil, fmt.Errorf("无效的范围格式")
				}
				suffix, parseErr := strconv.ParseInt(endStr, 10, 64)
				if parseErr != nil || suffix <= 0 {
					return nil, fmt.Errorf("无效的后缀长度")
				}
				start = fileSize - suffix
				if start < 0 {
					start = 0
				}
				end = fileSize - 1
			} else if endStr == "" {
				// 前缀范围：500- 表示从500字节到文件末尾
				start, err = strconv.ParseInt(startStr, 10, 64)
				if err != nil || start < 0 {
					return nil, fmt.Errorf("无效的起始位置")
				}
				end = fileSize - 1
			} else {
				// 完整范围：0-499
				start, err = strconv.ParseInt(startStr, 10, 64)
				if err != nil || start < 0 {
					return nil, fmt.Errorf("无效的起始位置")
				}
				end, err = strconv.ParseInt(endStr, 10, 64)

				if err != nil || end < start {
					return nil, fmt.Errorf("无效的结束位置")
				}
			}
		} else {
			return nil, fmt.Errorf("无效的范围格式")
		}

		// 验证范围有效性
		if start >= fileSize {
			return nil, fmt.Errorf("起始位置超出文件大小")
		}
		if end >= fileSize {
			end = fileSize - 1
		}

		ranges = append(ranges, Range{start: start, end: end})
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("没有有效的范围")
	}

	return ranges, nil
}

// fileDeleteHandler 删除指定文件或目录（支持递归删除）
func fileDeleteHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	relDir := r.URL.Query().Get("path")
	if fileName == "" {
		http.Error(w, "未指定文件", http.StatusBadRequest)
		return
	}
	targetDir, err := secureJoin(baseDir, relDir)
	if err != nil {
		http.Error(w, "无效的路径", http.StatusBadRequest)
		return
	}
	targetPath, err := secureJoin(targetDir, fileName)
	if err != nil {
		http.Error(w, "无效的文件名", http.StatusBadRequest)
		return
	}
	dirMu.Lock()
	err = os.RemoveAll(targetPath)
	dirMu.Unlock()
	if err != nil {
		http.Error(w, "删除失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "删除成功")
	} else {
		http.Redirect(w, r, "/?path="+relDir, http.StatusFound)
	}
}

// createHandler 根据参数在当前目录中创建新文件或文件夹
func createHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST方法", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	typ := r.FormValue("type")
	name := r.FormValue("name")
	relDir := r.FormValue("path")
	if name == "" {
		http.Error(w, "名称不能为空", http.StatusBadRequest)
		return
	}
	targetDir, err := secureJoin(baseDir, relDir)
	if err != nil {
		http.Error(w, "无效的路径", http.StatusBadRequest)
		return
	}
	targetPath, err := secureJoin(targetDir, name)
	if err != nil {
		http.Error(w, "无效的名称", http.StatusBadRequest)
		return
	}
	dirMu.Lock()
	defer dirMu.Unlock()
	switch typ {
	case "file":
		if _, err := os.Stat(targetPath); err == nil {
			http.Error(w, "文件已存在", http.StatusBadRequest)
			return
		}
		f, err := os.Create(targetPath)
		if err != nil {
			http.Error(w, "无法创建文件: "+err.Error(), http.StatusInternalServerError)
			return
		}
		f.Close()
		fmt.Fprint(w, "文件创建成功")
	case "folder":
		if err := os.Mkdir(targetPath, 0755); err != nil {
			http.Error(w, "无法创建文件夹: "+err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "文件夹创建成功")
	default:
		http.Error(w, "无效的类型", http.StatusBadRequest)
	}
}

// renameHandler 重命名指定的文件或目录
func renameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST方法", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	oldName := r.FormValue("old")
	newName := r.FormValue("new")
	relDir := r.FormValue("path")
	if oldName == "" || newName == "" {
		http.Error(w, "缺少参数", http.StatusBadRequest)
		return
	}
	oldPath, err := secureJoin(baseDir, filepath.Join(relDir, oldName))
	if err != nil {
		http.Error(w, "无效的旧名称", http.StatusBadRequest)
		return
	}
	newPath, err := secureJoin(baseDir, filepath.Join(relDir, newName))
	if err != nil {
		http.Error(w, "无效的新名称", http.StatusBadRequest)
		return
	}
	dirMu.Lock()
	defer dirMu.Unlock()
	if err := os.Rename(oldPath, newPath); err != nil {
		http.Error(w, "重命名失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "重命名成功")
}

// calculateFileSize 根据文件大小返回合理单位表示
func calculateFileSize(size int64) string {
	const (
		KB = 1024.0
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(size)
	unitIndex := 0
	for value >= 1024 && unitIndex < len(units)-1 {
		value /= 1024
		unitIndex++
	}
	return fmt.Sprintf("%.2f %s", value, units[unitIndex])
}

// loginHandler 显示登录页面
func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, loginTemplate)
}

// apiLoginHandler 处理登录API请求
func apiLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 解析请求体
	var loginReq struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		RememberMe bool   `json:"remember_me"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, `{"error":"无效的请求格式"}`, http.StatusBadRequest)
		return
	}

	// 验证用户名密码
	if loginReq.Username != username || loginReq.Password != password {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"用户名或密码错误"}`)
		return
	}

	// 生成token
	token := generateToken()

	// 设置token过期时间
	duration := 24 * time.Hour // 默认1天
	if loginReq.RememberMe {
		duration = 30 * 24 * time.Hour // 记住登录状态30天
	}

	addToken(token, duration)

	// 返回token信息
	tokenInfo := TokenInfo{
		Token:     token,
		ExpiresAt: time.Now().Add(duration),
	}

	json.NewEncoder(w).Encode(tokenInfo)
}

// logoutHandler 处理登出请求
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// 获取token
	cookie, err := r.Cookie("auth_token")
	if err == nil {
		// 删除token
		tokenMu.Lock()
		delete(tokens, cookie.Value)
		tokenMu.Unlock()
	}

	// 清除cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
	})

	// 重定向到登录页面
	http.Redirect(w, r, "/login", http.StatusFound)
}

func main() {
	port := flag.Int("port", 8080, "HTTP服务器端口")
	dirFlag := flag.String("dir", ".", "操作的目录，默认为当前目录")
	flag.StringVar(&username, "username", "", "基本认证用户名（可选）")
	flag.StringVar(&password, "password", "", "基本认证密码（可选）")
	flag.BoolVar(&tlsEnabled, "tls", true, "启用TLS/HTTPS")
	flag.StringVar(&certFile, "cert", "", "TLS证书文件路径")
	flag.StringVar(&keyFile, "key", "", "TLS私钥文件路径")
	flag.Parse()
	baseDir = *dirFlag
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		if err := os.MkdirAll(baseDir, 0755); err != nil {
			fmt.Printf("无法创建目录 %s: %v\n", baseDir, err)
			return
		}
	}
	// 登录相关路由（不需要认证）
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/api/login", apiLoginHandler)
	http.HandleFunc("/logout", logoutHandler)

	// 文件管理相关路由（需要认证）
	http.HandleFunc("/", authHandler(indexHandler))
	http.HandleFunc("/list", authHandler(listHandler))
	http.HandleFunc("/upload", authHandler(fileUploadHandler))
	http.HandleFunc("/download", authHandler(fileDownloadHandler))
	http.HandleFunc("/delete", authHandler(fileDeleteHandler))
	http.HandleFunc("/create", authHandler(createHandler))
	http.HandleFunc("/rename", authHandler(renameHandler))
	addr := fmt.Sprintf(":%d", *port)

	if tlsEnabled {
		// 检查是否提供了证书和密钥文件
		if certFile == "" || keyFile == "" {
			fmt.Println("未提供证书文件，正在生成自签名证书...")

			// 生成自签名证书
			certPEM, keyPEM, err := generateSelfSignedCert()
			if err != nil {
				fmt.Printf("生成自签名证书失败: %v\n", err)
				return
			}

			// 从内存中加载证书
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				fmt.Printf("加载证书失败: %v\n", err)
				return
			}

			// 创建TLS配置
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
			}

			// 创建HTTPS服务器
			server := &http.Server{
				Addr:      addr,
				TLSConfig: tlsConfig,
			}

			fmt.Println("自签名证书生成完成")
			fmt.Printf("HTTPS服务器启动在 %s 端口, 工作目录: %s\n", addr, baseDir)
			fmt.Printf("访问地址: https://localhost:%d\n", *port)
			if err := server.ListenAndServeTLS("", ""); err != nil {
				fmt.Printf("HTTPS服务器启动失败: %v\n", err)
			}
		} else {
			// 使用提供的证书文件
			fmt.Printf("HTTPS服务器启动在 %s 端口, 工作目录: %s\n", addr, baseDir)
			fmt.Printf("访问地址: https://localhost:%d\n", *port)
			if err := http.ListenAndServeTLS(addr, certFile, keyFile, nil); err != nil {
				fmt.Printf("HTTPS服务器启动失败: %v\n", err)
			}
		}
	} else {
		fmt.Printf("HTTP服务器启动在 %s 端口, 工作目录: %s\n", addr, baseDir)
		fmt.Printf("访问地址: http://localhost:%d\n", *port)
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Printf("HTTP服务器启动失败: %v\n", err)
		}
	}
}
