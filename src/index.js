// 完整 TMDB+ 平台代码 - 单文件版本
// 将此代码完全复制到 Cloudflare Worker 编辑器中

// ==================== 主应用入口 ====================
export default {
  async fetch(request, env, ctx) {
    try {
      // 解析 URL
      const url = new URL(request.url);
      const pathname = url.pathname;
      
      // 路由分发
      if (pathname.startsWith('/api')) {
        return handleApi(request, env, ctx);
      } else if (pathname.startsWith('/dashboard')) {
        return handleDashboard(request, env, ctx);
      } else {
        return handleHome(request, env, ctx);
      }
    } catch (error) {
      return new Response(`Internal Server Error: ${error.message}`, {
        status: 500,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }
  }
};

// ==================== 工具函数 ====================
async function sign(payload, secret) {
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload64 = btoa(JSON.stringify(payload));
  return `${header}.${payload64}.${base64}`;
}

async function verify(token, secret) {
  try {
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    const encoder = new TextEncoder();
    const data = encoder.encode(`${headerB64}.${payloadB64}`);
    const signature = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const isValid = await crypto.subtle.verify('HMAC', key, signature, data);
    if (!isValid) throw new Error('Invalid signature');
    const payload = JSON.parse(atob(payloadB64));
    return payload;
  } catch {
    throw new Error('Invalid token');
  }
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

async function comparePassword(password, hashedPassword) {
  const hash = await hashPassword(password);
  return hash === hashedPassword;
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// ==================== API 处理 ====================
async function handleApi(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname.replace('/api', '') || '/';
  const method = request.method;
  
  // 公共 API 路由
  if (method === 'GET' && path === '/') {
    return apiHome(request, env);
  }
  if (method === 'GET' && path === '/docs') {
    return apiDocs(request, env);
  }
  if (method === 'GET' && path.startsWith('/tmdb/search')) {
    return tmdbSearch(request, env);
  }
  if (method === 'GET' && path.startsWith('/tmdb/detail')) {
    return tmdbDetail(request, env);
  }
  if (method === 'GET' && path.startsWith('/contents/public')) {
    return getPublicContents(request, env);
  }
  if (method === 'POST' && path === '/register') {
    return userRegister(request, env);
  }
  if (method === 'POST' && path === '/login') {
    return userLogin(request, env);
  }
  
  // 需要认证的 API
  try {
    const authHeader = request.headers.get('Authorization');
    let user = null;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      user = await verify(token, env.JWT_SECRET);
    }
    
    // 用户相关 API
    if (method === 'GET' && path === '/user/profile') {
      if (!user) return jsonResponse({ success: false, message: '需要登录' }, 401);
      return getUserProfile(user, env);
    }
    if (method === 'PATCH' && path === '/user/password') {
      if (!user) return jsonResponse({ success: false, message: '需要登录' }, 401);
      return updateUserPassword(request, user, env);
    }
    if (method === 'POST' && path === '/contents') {
      if (!user) return jsonResponse({ success: false, message: '需要登录' }, 401);
      return submitContent(request, user, env);
    }
    if (method === 'GET' && path === '/contents/my') {
      if (!user) return jsonResponse({ success: false, message: '需要登录' }, 401);
      return getUserContents(user, env);
    }
    if (method === 'POST' && path === '/upload/image') {
      if (!user) return jsonResponse({ success: false, message: '需要登录' }, 401);
      return uploadImage(request, user, env);
    }
    
    // 管理员 API
    if (user && user.role === 'admin') {
      if (method === 'GET' && path === '/admin/users') {
        return getAllUsers(request, env);
      }
      if (method === 'PATCH' && path.match(/^\/admin\/users\/\d+\/role$/)) {
        return updateUserRole(request, env);
      }
      if (method === 'PATCH' && path.match(/^\/admin\/users\/\d+\/password$/)) {
        return resetUserPassword(request, env);
      }
      if (method === 'DELETE' && path.match(/^\/admin\/users\/\d+$/)) {
        return deleteUser(request, env);
      }
      if (method === 'GET' && path === '/admin/contents') {
        return getAllContents(request, env);
      }
      if (method === 'PATCH' && path.match(/^\/admin\/contents\/\d+\/status$/)) {
        return updateContentStatus(request, env);
      }
      if (method === 'DELETE' && path.match(/^\/admin\/contents\/\d+$/)) {
        return deleteContent(request, env);
      }
    }
    
  } catch (error) {
    return jsonResponse({ success: false, message: error.message }, 500);
  }
  
  return jsonResponse({ success: false, message: 'API 接口不存在' }, 404);
}

// ==================== API 实现 ====================
async function apiHome(request, env) {
  return jsonResponse({
    success: true,
    message: 'TMDB+ API 服务运行中',
    version: '1.0.0',
    endpoints: {
      public: [
        'GET    /api - API 首页',
        'GET    /api/docs - API 文档',
        'POST   /api/register - 用户注册',
        'POST   /api/login - 用户登录',
        'GET    /api/tmdb/search - 搜索 TMDB',
        'GET    /api/contents/public - 查看公开资料'
      ],
      private: [
        'GET    /api/user/profile - 获取用户信息',
        'PATCH  /api/user/password - 修改密码',
        'POST   /api/contents - 提交资料',
        'GET    /api/contents/my - 我的提交',
        'POST   /api/upload/image - 上传图片'
      ]
    }
  });
}

async function apiDocs(request, env) {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TMDB+ API 文档</title>
  <style>
    body { font-family: -apple-system, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
    .container { max-width: 1000px; margin: 0 auto; }
    .header { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }
    .endpoint { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .method { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; margin-right: 10px; }
    .get { background: #61affe; color: white; }
    .post { background: #49cc90; color: white; }
    .url { font-family: monospace; background: #f8f9fa; padding: 8px; border-radius: 4px; margin: 10px 0; word-break: break-all; }
    .try-btn { background: #667eea; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-top: 10px; }
    .try-btn:hover { background: #5a67d8; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>TMDB+ API 文档</h1>
      <p>开放 API 接口，无需登录即可调用部分接口</p>
    </div>
    
    <div class="endpoint">
      <span class="method post">POST</span>
      <strong>用户注册</strong>
      <div class="url">/api/register</div>
      <p>请求体：{ username, password, email }</p>
    </div>
    
    <div class="endpoint">
      <span class="method post">POST</span>
      <strong>用户登录</strong>
      <div class="url">/api/login</div>
      <p>请求体：{ username, password }</p>
    </div>
    
    <div class="endpoint">
      <span class="method get">GET</span>
      <strong>搜索 TMDB</strong>
      <div class="url">/api/tmdb/search?query=avatar&type=movie</div>
      <p>参数：query (必需), type (可选, movie/tv)</p>
    </div>
    
    <div class="endpoint">
      <span class="method get">GET</span>
      <strong>查看公开资料</strong>
      <div class="url">/api/contents/public</div>
      <p>获取所有已审核的资料</p>
    </div>
    
    <h2>在线测试</h2>
    <div>
      <select id="endpoint-select">
        <option value="/api/tmdb/search?query=avatar&type=movie">搜索电影</option>
        <option value="/api/contents/public">查看公开资料</option>
      </select>
      <button onclick="testEndpoint()" class="try-btn">测试接口</button>
      <pre id="test-result" style="background: #282c34; color: white; padding: 20px; border-radius: 5px; margin-top: 20px; white-space: pre-wrap;"></pre>
    </div>
  </div>
  
  <script>
    async function testEndpoint() {
      const select = document.getElementById('endpoint-select');
      const result = document.getElementById('test-result');
      result.textContent = '请求中...';
      
      try {
        const response = await fetch(select.value);
        const data = await response.json();
        result.textContent = JSON.stringify(data, null, 2);
      } catch (error) {
        result.textContent = '错误：' + error.message;
      }
    }
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

async function tmdbSearch(request, env) {
  const url = new URL(request.url);
  const query = url.searchParams.get('query');
  const type = url.searchParams.get('type') || 'movie';
  
  if (!query) {
    return jsonResponse({ success: false, message: '请输入搜索关键词' }, 400);
  }
  
  try {
    const tmdbUrl = `${env.TMDB_BASE_URL}/search/${type}?api_key=${env.TMDB_API_KEY}&language=zh-CN&query=${encodeURIComponent(query)}&page=1`;
    const response = await fetch(tmdbUrl);
    const data = await response.json();
    
    const results = data.results.map(item => ({
      tmdb_id: item.id,
      title: item.title || item.name,
      original_title: item.original_title || item.original_name,
      overview: item.overview,
      poster_path: item.poster_path ? `https://image.tmdb.org/t/p/w500${item.poster_path}` : '',
      release_date: item.release_date || item.first_air_date,
      type: type
    }));
    
    return jsonResponse({
      success: true,
      data: results
    });
  } catch (error) {
    return jsonResponse({ success: false, message: 'TMDB 搜索失败' }, 500);
  }
}

async function tmdbDetail(request, env) {
  const url = new URL(request.url);
  const tmdb_id = url.searchParams.get('tmdb_id');
  const type = url.searchParams.get('type') || 'movie';
  
  if (!tmdb_id) {
    return jsonResponse({ success: false, message: '请传入 TMDB ID' }, 400);
  }
  
  try {
    const tmdbUrl = `${env.TMDB_BASE_URL}/${type}/${tmdb_id}?api_key=${env.TMDB_API_KEY}&language=zh-CN`;
    const response = await fetch(tmdbUrl);
    const data = await response.json();
    
    const detail = {
      tmdb_id: data.id,
      title: data.title || data.name,
      original_title: data.original_title || data.original_name,
      overview: data.overview,
      poster_path: data.poster_path ? `https://image.tmdb.org/t/p/w500${data.poster_path}` : '',
      backdrop_path: data.backdrop_path ? `https://image.tmdb.org/t/p/w1280${data.backdrop_path}` : '',
      release_date: data.release_date || data.first_air_date,
      genre: data.genres?.map(g => g.name).join(',') || '',
      type: type,
      vote_average: data.vote_average
    };
    
    return jsonResponse({
      success: true,
      data: detail
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '获取详情失败' }, 500);
  }
}

async function getPublicContents(request, env) {
  try {
    const result = await env.DB.prepare(`
      SELECT c.*, u.username 
      FROM contents c 
      LEFT JOIN users u ON c.submitter_id = u.id 
      WHERE c.status = 'approved'
      ORDER BY c.created_at DESC 
      LIMIT 20
    `).all();
    
    const contents = result.results.map(item => ({
      ...item,
      custom_fields: JSON.parse(item.custom_fields || '{}')
    }));
    
    return jsonResponse({
      success: true,
      data: contents
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '获取公开资料失败' }, 500);
  }
}

async function userRegister(request, env) {
  try {
    const body = await request.json();
    const { username, password, email } = body;
    
    if (!username || !password || !email) {
      return jsonResponse({ success: false, message: '用户名、密码、邮箱不能为空' }, 400);
    }
    
    if (password.length < 6) {
      return jsonResponse({ success: false, message: '密码长度不能少于6位' }, 400);
    }
    
    const hashedPassword = await hashPassword(password);
    
    const result = await env.DB.prepare(
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)'
    ).bind(username, hashedPassword, email).run();
    
    return jsonResponse({
      success: true,
      message: '注册成功',
      data: { id: result.meta.last_insert_rowid, username, email }
    }, 201);
  } catch (error) {
    if (error.message.includes('UNIQUE')) {
      return jsonResponse({ success: false, message: '用户名或邮箱已存在' }, 400);
    }
    return jsonResponse({ success: false, message: '注册失败' }, 500);
  }
}

async function userLogin(request, env) {
  try {
    const body = await request.json();
    const { username, password } = body;
    
    if (!username || !password) {
      return jsonResponse({ success: false, message: '用户名和密码不能为空' }, 400);
    }
    
    const user = await env.DB.prepare(
      'SELECT id, username, email, role, password FROM users WHERE username = ?'
    ).bind(username).first();
    
    if (!user) {
      return jsonResponse({ success: false, message: '用户不存在' }, 404);
    }
    
    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      return jsonResponse({ success: false, message: '密码错误' }, 400);
    }
    
    const token = await sign(
      { id: user.id, username: user.username, role: user.role },
      env.JWT_SECRET
    );
    
    delete user.password;
    return jsonResponse({
      success: true,
      message: '登录成功',
      data: { user, token }
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '登录失败' }, 500);
  }
}

async function getUserProfile(user, env) {
  const userData = await env.DB.prepare(
    'SELECT id, username, email, role, created_at FROM users WHERE id = ?'
  ).bind(user.id).first();
  
  return jsonResponse({
    success: true,
    data: userData
  });
}

async function updateUserPassword(request, user, env) {
  try {
    const body = await request.json();
    const { oldPassword, newPassword } = body;
    
    if (!oldPassword || !newPassword) {
      return jsonResponse({ success: false, message: '原密码和新密码不能为空' }, 400);
    }
    if (newPassword.length < 6) {
      return jsonResponse({ success: false, message: '新密码长度不能少于6位' }, 400);
    }
    
    const dbUser = await env.DB.prepare(
      'SELECT password FROM users WHERE id = ?'
    ).bind(user.id).first();
    
    const isOldPasswordValid = await comparePassword(oldPassword, dbUser.password);
    if (!isOldPasswordValid) {
      return jsonResponse({ success: false, message: '原密码错误' }, 400);
    }
    
    const hashedNewPassword = await hashPassword(newPassword);
    await env.DB.prepare(
      'UPDATE users SET password = ? WHERE id = ?'
    ).bind(hashedNewPassword, user.id).run();
    
    return jsonResponse({
      success: true,
      message: '密码修改成功'
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '密码修改失败' }, 500);
  }
}

async function submitContent(request, user, env) {
  try {
    const body = await request.json();
    const { tmdb_id, type, title, description, poster_url, custom_fields } = body;
    
    if (!type || !title) {
      return jsonResponse({ success: false, message: '类型和标题不能为空' }, 400);
    }
    
    let contentData = {
      title,
      type,
      description: description || '',
      poster_url: poster_url || '',
      tmdb_id: tmdb_id || '',
      custom_fields: custom_fields ? JSON.stringify(custom_fields) : '{}'
    };
    
    if (tmdb_id && type !== 'other') {
      try {
        const tmdbUrl = `${env.TMDB_BASE_URL}/${type}/${tmdb_id}?api_key=${env.TMDB_API_KEY}&language=zh-CN`;
        const response = await fetch(tmdbUrl);
        const tmdbDetail = await response.json();
        
        contentData.title = title || (tmdbDetail.title || tmdbDetail.name);
        contentData.description = description || tmdbDetail.overview || '';
        contentData.poster_url = poster_url || (tmdbDetail.poster_path ? `https://image.tmdb.org/t/p/w500${tmdbDetail.poster_path}` : '');
      } catch (error) {
        // 使用手动填写的数据
      }
    }
    
    const result = await env.DB.prepare(
      `INSERT INTO contents (
        title, type, description, poster_url, tmdb_id, custom_fields, submitter_id, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      contentData.title,
      contentData.type,
      contentData.description,
      contentData.poster_url,
      contentData.tmdb_id,
      contentData.custom_fields,
      user.id,
      'pending'
    ).run();
    
    return jsonResponse({
      success: true,
      message: '资料提交成功',
      data: {
        id: result.meta.last_insert_rowid,
        ...contentData,
        status: 'pending'
      }
    }, 201);
  } catch (error) {
    return jsonResponse({ success: false, message: '提交失败' }, 500);
  }
}

async function getUserContents(user, env) {
  try {
    const contents = await env.DB.prepare(
      'SELECT * FROM contents WHERE submitter_id = ? ORDER BY created_at DESC'
    ).bind(user.id).all();
    
    const formatted = contents.results.map(item => ({
      ...item,
      custom_fields: JSON.parse(item.custom_fields || '{}')
    }));
    
    return jsonResponse({
      success: true,
      data: formatted
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '获取失败' }, 500);
  }
}

async function uploadImage(request, user, env) {
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    
    if (!file) {
      return jsonResponse({ success: false, message: '请选择要上传的图片' }, 400);
    }
    
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (!allowedTypes.includes(file.type)) {
      return jsonResponse({ success: false, message: '仅支持 JPG/PNG/WEBP/GIF 格式图片' }, 400);
    }
    
    const fileName = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}.${file.type.split('/')[1]}`;
    const arrayBuffer = await file.arrayBuffer();
    
    await env.IMAGE_BUCKET.put(fileName, arrayBuffer, {
      httpMetadata: { contentType: file.type }
    });
    
    const imageUrl = `${env.R2_PUBLIC_DOMAIN}/${fileName}`;
    return jsonResponse({
      success: true,
      message: '图片上传成功',
      data: { imageUrl, fileName }
    }, 201);
  } catch (error) {
    return jsonResponse({ success: false, message: '图片上传失败' }, 500);
  }
}

// ==================== 管理员 API ====================
async function getAllUsers(request, env) {
  try {
    const users = await env.DB.prepare(
      'SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC'
    ).all();
    
    return jsonResponse({
      success: true,
      data: users.results
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '获取用户列表失败' }, 500);
  }
}

async function updateUserRole(request, env) {
  try {
    const url = new URL(request.url);
    const id = url.pathname.split('/')[3];
    const body = await request.json();
    const { role } = body;
    
    if (!['user', 'admin'].includes(role)) {
      return jsonResponse({ success: false, message: '角色只能是 user 或 admin' }, 400);
    }
    
    await env.DB.prepare(
      'UPDATE users SET role = ? WHERE id = ?'
    ).bind(role, id).run();
    
    return jsonResponse({
      success: true,
      message: `用户角色已修改为 ${role}`
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '修改角色失败' }, 500);
  }
}

async function resetUserPassword(request, env) {
  try {
    const url = new URL(request.url);
    const id = url.pathname.split('/')[3];
    const body = await request.json();
    const { newPassword } = body;
    
    if (!newPassword || newPassword.length < 6) {
      return jsonResponse({ success: false, message: '新密码不能为空且长度不能少于6位' }, 400);
    }
    
    const hashedPassword = await hashPassword(newPassword);
    await env.DB.prepare(
      'UPDATE users SET password = ? WHERE id = ?'
    ).bind(hashedPassword, id).run();
    
    return jsonResponse({
      success: true,
      message: '密码重置成功'
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '重置密码失败' }, 500);
  }
}

async function deleteUser(request, env) {
  try {
    const url = new URL(request.url);
    const id = url.pathname.split('/')[3];
    
    // 先删除用户的内容
    await env.DB.prepare(
      'DELETE FROM contents WHERE submitter_id = ?'
    ).bind(id).run();
    
    // 删除用户
    await env.DB.prepare(
      'DELETE FROM users WHERE id = ?'
    ).bind(id).run();
    
    return jsonResponse({
      success: true,
      message: '用户删除成功'
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '删除用户失败' }, 500);
  }
}

async function getAllContents(request, env) {
  try {
    const contents = await env.DB.prepare(`
      SELECT c.*, u.username as submitter_name 
      FROM contents c 
      LEFT JOIN users u ON c.submitter_id = u.id 
      ORDER BY c.created_at DESC
    `).all();
    
    const formatted = contents.results.map(item => ({
      ...item,
      custom_fields: JSON.parse(item.custom_fields || '{}')
    }));
    
    return jsonResponse({
      success: true,
      data: formatted
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '获取资料失败' }, 500);
  }
}

async function updateContentStatus(request, env) {
  try {
    const url = new URL(request.url);
    const id = url.pathname.split('/')[3];
    const body = await request.json();
    const { status } = body;
    
    if (!['approved', 'rejected', 'pending'].includes(status)) {
      return jsonResponse({ success: false, message: '状态只能是 approved/rejected/pending' }, 400);
    }
    
    await env.DB.prepare(
      'UPDATE contents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(status, id).run();
    
    return jsonResponse({
      success: true,
      message: `资料状态已更新为 ${status}`
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '更新状态失败' }, 500);
  }
}

async function deleteContent(request, env) {
  try {
    const url = new URL(request.url);
    const id = url.pathname.split('/')[3];
    
    await env.DB.prepare(
      'DELETE FROM contents WHERE id = ?'
    ).bind(id).run();
    
    return jsonResponse({
      success: true,
      message: '资料删除成功'
    });
  } catch (error) {
    return jsonResponse({ success: false, message: '删除失败' }, 500);
  }
}

// ==================== 仪表板处理 ====================
async function handleDashboard(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname.replace('/dashboard', '') || '/';
  
  // 登录页面
  if (path === '/login' || path === '/login/') {
    return showLoginPage();
  }
  
  // 注册页面
  if (path === '/register' || path === '/register/') {
    return showRegisterPage();
  }
  
  // 检查认证
  const token = await getTokenFromRequest(request);
  if (!token) {
    return Response.redirect(new URL('/dashboard/login', request.url).toString());
  }
  
  try {
    const user = await verify(token, env.JWT_SECRET);
    
    // 仪表板首页
    if (path === '/' || path === '') {
      return showDashboardHome(user, env);
    }
    
    // 我的提交
    if (path === '/contents' || path === '/contents/') {
      return showUserContents(user, env);
    }
    
    // 提交资料
    if (path === '/submit' || path === '/submit/') {
      return showSubmitPage(user, env);
    }
    
    // 个人设置
    if (path === '/profile' || path === '/profile/') {
      return showProfilePage(user, env);
    }
    
    // 管理员页面
    if (user.role === 'admin') {
      if (path === '/admin/users' || path === '/admin/users/') {
        return showAdminUsers(user, env);
      }
      if (path === '/admin/contents' || path === '/admin/contents/') {
        return showAdminContents(user, env);
      }
    }
    
    // 404
    return showDashboard404();
    
  } catch (error) {
    // Token 无效，跳转到登录页
    return Response.redirect(new URL('/dashboard/login', request.url).toString());
  }
}

function getTokenFromRequest(request) {
  // 从 Cookie 获取
  const cookieHeader = request.headers.get('Cookie');
  if (cookieHeader) {
    const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
      const [name, value] = cookie.trim().split('=');
      acc[name] = value;
      return acc;
    }, {});
    return cookies.token;
  }
  return null;
}

// ==================== 仪表板页面 ====================
function showLoginPage() {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .login-bg {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
  </style>
</head>
<body class="login-bg min-h-screen flex items-center justify-center p-4">
  <div class="max-w-md w-full">
    <div class="bg-white rounded-2xl shadow-xl p-8">
      <div class="text-center mb-8">
        <h1 class="text-3xl font-bold text-gray-800 mb-2">
          <i class="fas fa-film text-purple-600"></i> TMDB+
        </h1>
        <p class="text-gray-600">登录您的账号</p>
      </div>
      
      <form id="loginForm" class="space-y-6">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-2">用户名</label>
          <input type="text" id="username" required 
            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
        </div>
        
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-2">密码</label>
          <input type="password" id="password" required 
            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
        </div>
        
        <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white py-3 px-4 rounded-lg font-semibold hover:opacity-90 transition">
          登录
        </button>
        
        <div class="text-center mt-4">
          <p class="text-gray-600">还没有账号？ <a href="/dashboard/register" class="text-purple-600 font-semibold">立即注册</a></p>
        </div>
      </form>
      
      <div id="message" class="mt-4 hidden p-3 rounded-lg"></div>
    </div>
    
    <div class="text-center mt-6 text-white text-sm">
      <p>© 2024 TMDB+ 平台 | 默认管理员账号：admin / admin</p>
    </div>
  </div>
  
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const message = document.getElementById('message');
      
      message.className = 'mt-4 hidden p-3 rounded-lg';
      message.textContent = '';
      
      try {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
          // 保存 token 到 cookie
          document.cookie = \`token=\${data.data.token}; Path=/; Max-Age=604800;\`;
          
          message.className = 'mt-4 p-3 rounded-lg bg-green-100 text-green-700';
          message.textContent = '登录成功，正在跳转...';
          
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 1000);
        } else {
          message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
          message.textContent = data.message;
        }
      } catch (error) {
        message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
        message.textContent = '登录失败，请检查网络连接';
      }
    });
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function showRegisterPage() {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>注册 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .register-bg {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
  </style>
</head>
<body class="register-bg min-h-screen flex items-center justify-center p-4">
  <div class="max-w-md w-full">
    <div class="bg-white rounded-2xl shadow-xl p-8">
      <div class="text-center mb-8">
        <h1 class="text-3xl font-bold text-gray-800 mb-2">
          <i class="fas fa-film text-purple-600"></i> TMDB+
        </h1>
        <p class="text-gray-600">创建新账号</p>
      </div>
      
      <form id="registerForm" class="space-y-6">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-2">用户名</label>
          <input type="text" id="username" required 
            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
        </div>
        
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-2">邮箱</label>
          <input type="email" id="email" required 
            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
        </div>
        
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-2">密码</label>
          <input type="password" id="password" required 
            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
          <p class="text-xs text-gray-500 mt-1">至少6个字符</p>
        </div>
        
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-2">确认密码</label>
          <input type="password" id="confirmPassword" required 
            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
        </div>
        
        <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white py-3 px-4 rounded-lg font-semibold hover:opacity-90 transition">
          注册
        </button>
        
        <div class="text-center mt-4">
          <p class="text-gray-600">已有账号？ <a href="/dashboard/login" class="text-purple-600 font-semibold">立即登录</a></p>
        </div>
      </form>
      
      <div id="message" class="mt-4 hidden p-3 rounded-lg"></div>
    </div>
  </div>
  
  <script>
    document.getElementById('registerForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirmPassword').value;
      const message = document.getElementById('message');
      
      message.className = 'mt-4 hidden p-3 rounded-lg';
      message.textContent = '';
      
      if (password !== confirmPassword) {
        message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
        message.textContent = '两次输入的密码不一致';
        return;
      }
      
      if (password.length < 6) {
        message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
        message.textContent = '密码长度不能少于6位';
        return;
      }
      
      try {
        const response = await fetch('/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
          message.className = 'mt-4 p-3 rounded-lg bg-green-100 text-green-700';
          message.textContent = '注册成功！正在跳转到登录页面...';
          
          setTimeout(() => {
            window.location.href = '/dashboard/login';
          }, 1500);
        } else {
          message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
          message.textContent = data.message;
        }
      } catch (error) {
        message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
        message.textContent = '注册失败，请检查网络连接';
      }
    });
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function showDashboardHome(user, env) {
  const isAdmin = user.role === 'admin';
  
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>仪表板 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .sidebar {
      background: linear-gradient(to bottom, #667eea, #764ba2);
    }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="flex">
    <!-- 侧边栏 -->
    <div class="sidebar text-white w-64 min-h-screen p-6">
      <div class="mb-8">
        <h1 class="text-2xl font-bold">
          <i class="fas fa-film mr-2"></i>TMDB+
        </h1>
      </div>
      
      <div class="mb-8">
        <div class="flex items-center mb-4">
          <div class="w-10 h-10 rounded-full bg-purple-600 flex items-center justify-center mr-3">
            <i class="fas fa-user"></i>
          </div>
          <div>
            <p class="font-semibold">${user.username}</p>
            <p class="text-sm text-purple-300">${isAdmin ? '管理员' : '用户'}</p>
          </div>
        </div>
      </div>
      
      <nav class="space-y-2">
        <a href="/dashboard" class="block py-3 px-4 rounded-lg hover:bg-purple-700 bg-purple-700">
          <i class="fas fa-home mr-3"></i>仪表板
        </a>
        <a href="/dashboard/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-photo-video mr-3"></i>我的提交
        </a>
        <a href="/dashboard/submit" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-plus-circle mr-3"></i>提交资料
        </a>
        <a href="/dashboard/profile" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-user-cog mr-3"></i>个人设置
        </a>
        
        ${isAdmin ? `
        <div class="mt-8 pt-6 border-t border-purple-700">
          <p class="px-4 text-sm text-purple-300 mb-3">管理</p>
          <a href="/dashboard/admin/users" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-users mr-3"></i>用户管理
          </a>
          <a href="/dashboard/admin/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-tasks mr-3"></i>内容审核
          </a>
        </div>
        ` : ''}
        
        <div class="mt-8 pt-6 border-t border-purple-700">
          <a href="/api/docs" target="_blank" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-code mr-3"></i>API 文档
          </a>
          <a href="/" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-globe mr-3"></i>网站首页
          </a>
          <button onclick="logout()" class="block w-full text-left py-3 px-4 rounded-lg hover:bg-red-700">
            <i class="fas fa-sign-out-alt mr-3"></i>退出登录
          </button>
        </div>
      </nav>
    </div>
    
    <!-- 主内容 -->
    <div class="flex-1 p-6">
      <div class="mb-8">
        <h2 class="text-2xl font-bold text-gray-800">仪表板</h2>
        <p class="text-gray-600">欢迎回来，${user.username}！</p>
      </div>
      
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div class="bg-gradient-to-r from-purple-500 to-pink-500 rounded-xl p-6 text-white">
          <div class="flex justify-between items-start">
            <div>
              <p class="text-sm opacity-90">我的提交</p>
              <h3 id="myContentsCount" class="text-3xl font-bold mt-2">-</h3>
            </div>
            <i class="fas fa-photo-video text-2xl opacity-80"></i>
          </div>
          <p class="text-sm opacity-90 mt-4">已提交的资料数量</p>
        </div>
        
        <div class="bg-gradient-to-r from-blue-500 to-cyan-500 rounded-xl p-6 text-white">
          <div class="flex justify-between items-start">
            <div>
              <p class="text-sm opacity-90">已审核</p>
              <h3 id="approvedCount" class="text-3xl font-bold mt-2">-</h3>
            </div>
            <i class="fas fa-check-circle text-2xl opacity-80"></i>
          </div>
          <p class="text-sm opacity-90 mt-4">已通过审核的资料</p>
        </div>
        
        <div class="bg-gradient-to-r from-green-500 to-emerald-500 rounded-xl p-6 text-white">
          <div class="flex justify-between items-start">
            <div>
              <p class="text-sm opacity-90">待审核</p>
              <h3 id="pendingCount" class="text-3xl font-bold mt-2">-</h3>
            </div>
            <i class="fas fa-clock text-2xl opacity-80"></i>
          </div>
          <p class="text-sm opacity-90 mt-4">等待审核的资料</p>
        </div>
      </div>
      
      <div class="bg-white rounded-xl shadow-sm p-6">
        <h3 class="text-lg font-semibold mb-4">快速操作</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <a href="/dashboard/submit" class="block bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded-lg p-4 text-center transition">
            <i class="fas fa-plus-circle text-purple-600 text-2xl mb-2"></i>
            <p class="font-medium text-gray-800">提交资料</p>
            <p class="text-sm text-gray-600 mt-1">新增影视资料</p>
          </a>
          
          <a href="/dashboard/contents" class="block bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg p-4 text-center transition">
            <i class="fas fa-list text-blue-600 text-2xl mb-2"></i>
            <p class="font-medium text-gray-800">我的提交</p>
            <p class="text-sm text-gray-600 mt-1">查看已提交的资料</p>
          </a>
          
          <a href="/api/docs" target="_blank" class="block bg-green-50 hover:bg-green-100 border border-green-200 rounded-lg p-4 text-center transition">
            <i class="fas fa-code text-green-600 text-2xl mb-2"></i>
            <p class="font-medium text-gray-800">API 文档</p>
            <p class="text-sm text-gray-600 mt-1">查看完整 API 文档</p>
          </a>
        </div>
      </div>
      
      ${isAdmin ? `
      <div class="mt-8 bg-gradient-to-r from-purple-900 to-purple-800 rounded-xl shadow-sm p-6 text-white">
        <h3 class="text-lg font-semibold mb-4">管理员面板</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <a href="/dashboard/admin/users" class="block bg-white/10 hover:bg-white/20 rounded-lg p-4 border border-white/20 transition">
            <div class="flex items-center">
              <i class="fas fa-users text-xl mr-3"></i>
              <div>
                <p class="font-medium">用户管理</p>
                <p class="text-sm opacity-80">管理所有用户账号</p>
              </div>
            </div>
          </a>
          
          <a href="/dashboard/admin/contents" class="block bg-white/10 hover:bg-white/20 rounded-lg p-4 border border-white/20 transition">
            <div class="flex items-center">
              <i class="fas fa-tasks text-xl mr-3"></i>
              <div>
                <p class="font-medium">内容审核</p>
                <p class="text-sm opacity-80">审核用户提交的资料</p>
              </div>
            </div>
          </a>
        </div>
      </div>
      ` : ''}
    </div>
  </div>
  
  <script>
    function logout() {
      document.cookie = 'token=; Path=/; Max-Age=0';
      window.location.href = '/dashboard/login';
    }
    
    async function loadDashboardData() {
      try {
        const response = await fetch('/api/contents/my', {
          headers: {
            'Authorization': 'Bearer ' + getCookie('token')
          }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.success) {
            const contents = data.data;
            const total = contents.length;
            const approved = contents.filter(c => c.status === 'approved').length;
            const pending = contents.filter(c => c.status === 'pending').length;
            
            document.getElementById('myContentsCount').textContent = total;
            document.getElementById('approvedCount').textContent = approved;
            document.getElementById('pendingCount').textContent = pending;
          }
        }
      } catch (error) {
        console.error('加载数据失败:', error);
      }
    }
    
    function getCookie(name) {
      const value = \`; \${document.cookie}\`;
      const parts = value.split(\`; \${name}=\`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    }
    
    document.addEventListener('DOMContentLoaded', loadDashboardData);
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function showUserContents(user, env) {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>我的提交 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .sidebar {
      background: linear-gradient(to bottom, #667eea, #764ba2);
    }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="flex">
    <div class="sidebar text-white w-64 min-h-screen p-6">
      <div class="mb-8">
        <h1 class="text-2xl font-bold">
          <i class="fas fa-film mr-2"></i>TMDB+
        </h1>
      </div>
      
      <nav class="space-y-2">
        <a href="/dashboard" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-home mr-3"></i>仪表板
        </a>
        <a href="/dashboard/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700 bg-purple-700">
          <i class="fas fa-photo-video mr-3"></i>我的提交
        </a>
        <a href="/dashboard/submit" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-plus-circle mr-3"></i>提交资料
        </a>
        <a href="/dashboard/profile" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-user-cog mr-3"></i>个人设置
        </a>
        
        ${user.role === 'admin' ? `
        <div class="mt-8 pt-6 border-t border-purple-700">
          <p class="px-4 text-sm text-purple-300 mb-3">管理</p>
          <a href="/dashboard/admin/users" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-users mr-3"></i>用户管理
          </a>
          <a href="/dashboard/admin/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-tasks mr-3"></i>内容审核
          </a>
        </div>
        ` : ''}
        
        <div class="mt-8 pt-6 border-t border-purple-700">
          <a href="/" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-globe mr-3"></i>网站首页
          </a>
          <button onclick="logout()" class="block w-full text-left py-3 px-4 rounded-lg hover:bg-red-700">
            <i class="fas fa-sign-out-alt mr-3"></i>退出登录
          </button>
        </div>
      </nav>
    </div>
    
    <div class="flex-1 p-6">
      <div class="flex justify-between items-center mb-6">
        <h2 class="text-2xl font-bold text-gray-800">我的提交</h2>
        <a href="/dashboard/submit" class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg flex items-center">
          <i class="fas fa-plus mr-2"></i> 新提交
        </a>
      </div>
      
      <div class="bg-white rounded-xl shadow-sm p-6">
        <div id="contentsList" class="space-y-4">
          <div class="text-center py-8 text-gray-500">
            <i class="fas fa-spinner fa-spin text-2xl mb-2"></i>
            <p>加载中...</p>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    function logout() {
      document.cookie = 'token=; Path=/; Max-Age=0';
      window.location.href = '/dashboard/login';
    }
    
    function getCookie(name) {
      const value = \`; \${document.cookie}\`;
      const parts = value.split(\`; \${name}=\`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    }
    
    async function loadContents() {
      try {
        const response = await fetch('/api/contents/my', {
          headers: {
            'Authorization': 'Bearer ' + getCookie('token')
          }
        });
        
        const data = await response.json();
        const container = document.getElementById('contentsList');
        
        if (data.success && data.data.length > 0) {
          container.innerHTML = data.data.map(item => \`
            <div class="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <div class="flex items-start">
                    \${item.poster_url ? \`
                      <img src="\${item.poster_url}" alt="\${item.title}" class="w-16 h-24 object-cover rounded mr-4">
                    \` : \`
                      <div class="w-16 h-24 bg-gray-200 rounded mr-4 flex items-center justify-center">
                        <i class="fas fa-film text-gray-400 text-xl"></i>
                      </div>
                    \`}
                    <div>
                      <h3 class="font-bold text-lg text-gray-800">\${item.title}</h3>
                      <div class="flex items-center space-x-4 mt-2">
                        <span class="px-2 py-1 text-xs rounded-full \${item.type === 'movie' ? 'bg-blue-100 text-blue-800' : 'bg-green-100 text-green-800'}">
                          \${item.type === 'movie' ? '电影' : '电视剧'}
                        </span>
                        <span class="px-2 py-1 text-xs rounded-full \${item.status === 'approved' ? 'bg-green-100 text-green-800' : item.status === 'rejected' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}">
                          \${item.status === 'approved' ? '已审核' : item.status === 'rejected' ? '已拒绝' : '待审核'}
                        </span>
                        <span class="text-sm text-gray-500">
                          \${new Date(item.created_at).toLocaleDateString('zh-CN')}
                        </span>
                      </div>
                      \${item.description ? \`
                        <p class="text-gray-600 mt-2 line-clamp-2">\${item.description}</p>
                      \` : ''}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          \`).join('');
        } else {
          container.innerHTML = \`
            <div class="text-center py-8">
              <i class="fas fa-inbox text-3xl text-gray-300 mb-2"></i>
              <p class="text-gray-500">暂无提交记录</p>
              <a href="/dashboard/submit" class="text-purple-600 hover:text-purple-800 mt-2 inline-block">
                开始你的第一次提交
              </a>
            </div>
          \`;
        }
      } catch (error) {
        document.getElementById('contentsList').innerHTML = \`
          <div class="text-center py-8 text-red-500">
            <i class="fas fa-exclamation-triangle text-2xl mb-2"></i>
            <p>加载失败：\${error.message}</p>
          </div>
        \`;
      }
    }
    
    document.addEventListener('DOMContentLoaded', loadContents);
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function showSubmitPage(user, env) {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>提交资料 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .sidebar {
      background: linear-gradient(to bottom, #667eea, #764ba2);
    }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="flex">
    <div class="sidebar text-white w-64 min-h-screen p-6">
      <div class="mb-8">
        <h1 class="text-2xl font-bold">
          <i class="fas fa-film mr-2"></i>TMDB+
        </h1>
      </div>
      
      <nav class="space-y-2">
        <a href="/dashboard" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-home mr-3"></i>仪表板
        </a>
        <a href="/dashboard/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-photo-video mr-3"></i>我的提交
        </a>
        <a href="/dashboard/submit" class="block py-3 px-4 rounded-lg hover:bg-purple-700 bg-purple-700">
          <i class="fas fa-plus-circle mr-3"></i>提交资料
        </a>
        <a href="/dashboard/profile" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-user-cog mr-3"></i>个人设置
        </a>
        
        ${user.role === 'admin' ? `
        <div class="mt-8 pt-6 border-t border-purple-700">
          <p class="px-4 text-sm text-purple-300 mb-3">管理</p>
          <a href="/dashboard/admin/users" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-users mr-3"></i>用户管理
          </a>
          <a href="/dashboard/admin/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-tasks mr-3"></i>内容审核
          </a>
        </div>
        ` : ''}
        
        <div class="mt-8 pt-6 border-t border-purple-700">
          <a href="/" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-globe mr-3"></i>网站首页
          </a>
          <button onclick="logout()" class="block w-full text-left py-3 px-4 rounded-lg hover:bg-red-700">
            <i class="fas fa-sign-out-alt mr-3"></i>退出登录
          </button>
        </div>
      </nav>
    </div>
    
    <div class="flex-1 p-6">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">提交资料</h2>
      
      <div class="bg-white rounded-xl shadow-sm p-6">
        <form id="submitForm" class="space-y-6">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">类型 *</label>
              <select id="type" required 
                class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
                <option value="">选择类型</option>
                <option value="movie">电影</option>
                <option value="tv">电视剧</option>
                <option value="other">其他</option>
              </select>
            </div>
            
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">标题 *</label>
              <input type="text" id="title" required 
                class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
            </div>
          </div>
          
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">描述</label>
            <textarea id="description" rows="4" 
              class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"></textarea>
          </div>
          
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">海报 URL（可选）</label>
            <input type="url" id="poster_url" 
              class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              placeholder="https://example.com/poster.jpg">
          </div>
          
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">TMDB ID（可选）</label>
            <input type="number" id="tmdb_id" 
              class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              placeholder="例如：19995（阿凡达）">
            <p class="text-xs text-gray-500 mt-1">填写 TMDB ID 可以自动补全信息</p>
          </div>
          
          <div class="flex justify-end">
            <button type="submit" class="bg-gradient-to-r from-purple-600 to-blue-600 text-white px-8 py-3 rounded-lg font-semibold hover:opacity-90">
              <i class="fas fa-paper-plane mr-2"></i>提交资料
            </button>
          </div>
        </form>
        
        <div id="message" class="mt-4 hidden p-3 rounded-lg"></div>
        
        <div class="mt-8 bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h4 class="font-medium text-blue-800 mb-2"><i class="fas fa-info-circle mr-2"></i>提交说明</h4>
          <ul class="text-sm text-blue-700 space-y-1">
            <li>• 填写 TMDB ID 可以自动从 TMDB 数据库补全信息</li>
            <li>• 提交的资料需要管理员审核后才能公开显示</li>
            <li>• 可以在"我的提交"中查看审核状态</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    function logout() {
      document.cookie = 'token=; Path=/; Max-Age=0';
      window.location.href = '/dashboard/login';
    }
    
    function getCookie(name) {
      const value = \`; \${document.cookie}\`;
      const parts = value.split(\`; \${name}=\`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    }
    
    document.getElementById('submitForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const type = document.getElementById('type').value;
      const title = document.getElementById('title').value;
      const description = document.getElementById('description').value;
      const poster_url = document.getElementById('poster_url').value;
      const tmdb_id = document.getElementById('tmdb_id').value;
      const message = document.getElementById('message');
      
      message.className = 'mt-4 hidden p-3 rounded-lg';
      message.textContent = '';
      
      if (!type || !title) {
        showMessage('类型和标题不能为空', 'error');
        return;
      }
      
      try {
        const token = getCookie('token');
        const response = await fetch('/api/contents', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            type,
            title,
            description,
            poster_url,
            tmdb_id: tmdb_id || ''
          })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showMessage(data.message, 'success');
          document.getElementById('submitForm').reset();
          
          setTimeout(() => {
            window.location.href = '/dashboard/contents';
          }, 2000);
        } else {
          showMessage(data.message, 'error');
        }
      } catch (error) {
        showMessage('提交失败：' + error.message, 'error');
      }
    });
    
    function showMessage(text, type = 'info') {
      const message = document.getElementById('message');
      message.className = \`mt-4 p-3 rounded-lg \${type === 'error' ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}\`;
      message.textContent = text;
      message.classList.remove('hidden');
    }
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function showProfilePage(user, env) {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>个人设置 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .sidebar {
      background: linear-gradient(to bottom, #667eea, #764ba2);
    }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="flex">
    <div class="sidebar text-white w-64 min-h-screen p-6">
      <div class="mb-8">
        <h1 class="text-2xl font-bold">
          <i class="fas fa-film mr-2"></i>TMDB+
        </h1>
      </div>
      
      <nav class="space-y-2">
        <a href="/dashboard" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-home mr-3"></i>仪表板
        </a>
        <a href="/dashboard/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-photo-video mr-3"></i>我的提交
        </a>
        <a href="/dashboard/submit" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-plus-circle mr-3"></i>提交资料
        </a>
        <a href="/dashboard/profile" class="block py-3 px-4 rounded-lg hover:bg-purple-700 bg-purple-700">
          <i class="fas fa-user-cog mr-3"></i>个人设置
        </a>
        
        ${user.role === 'admin' ? `
        <div class="mt-8 pt-6 border-t border-purple-700">
          <p class="px-4 text-sm text-purple-300 mb-3">管理</p>
          <a href="/dashboard/admin/users" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-users mr-3"></i>用户管理
          </a>
          <a href="/dashboard/admin/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-tasks mr-3"></i>内容审核
          </a>
        </div>
        ` : ''}
        
        <div class="mt-8 pt-6 border-t border-purple-700">
          <a href="/" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-globe mr-3"></i>网站首页
          </a>
          <button onclick="logout()" class="block w-full text-left py-3 px-4 rounded-lg hover:bg-red-700">
            <i class="fas fa-sign-out-alt mr-3"></i>退出登录
          </button>
        </div>
      </nav>
    </div>
    
    <div class="flex-1 p-6">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">个人设置</h2>
      
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-2 space-y-6">
          <div class="bg-white rounded-xl shadow-sm p-6">
            <h3 class="text-lg font-semibold mb-4">个人信息</h3>
            <div class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">用户名</label>
                <div class="px-4 py-3 bg-gray-50 rounded-lg border border-gray-200">
                  <p class="font-medium">${user.username}</p>
                </div>
              </div>
              
              <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">角色</label>
                <div class="px-4 py-3 bg-gray-50 rounded-lg border border-gray-200">
                  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800'}">
                    ${user.role === 'admin' ? '管理员' : '普通用户'}
                  </span>
                </div>
              </div>
            </div>
          </div>
          
          <div class="bg-white rounded-xl shadow-sm p-6">
            <h3 class="text-lg font-semibold mb-4">修改密码</h3>
            <form id="passwordForm" class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">当前密码</label>
                <input type="password" id="currentPassword" required 
                  class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
              </div>
              
              <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">新密码</label>
                <input type="password" id="newPassword" required 
                  class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
                <p class="text-xs text-gray-500 mt-1">至少6个字符</p>
              </div>
              
              <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">确认新密码</label>
                <input type="password" id="confirmNewPassword" required 
                  class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
              </div>
              
              <button type="submit" class="bg-gradient-to-r from-purple-600 to-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:opacity-90">
                修改密码
              </button>
            </form>
            
            <div id="passwordMessage" class="mt-4 hidden p-3 rounded-lg"></div>
          </div>
        </div>
        
        <div>
          <div class="bg-white rounded-xl shadow-sm p-6 mb-6">
            <h3 class="text-lg font-semibold mb-4">账户统计</h3>
            <div class="space-y-4">
              <div>
                <p class="text-sm text-gray-500 mb-1">总提交数</p>
                <p id="totalSubmissions" class="text-2xl font-bold text-gray-800">-</p>
              </div>
              
              <div>
                <p class="text-sm text-gray-500 mb-1">已审核</p>
                <p id="approvedSubmissions" class="text-2xl font-bold text-green-600">-</p>
              </div>
              
              <div>
                <p class="text-sm text-gray-500 mb-1">待审核</p>
                <p id="pendingSubmissions" class="text-2xl font-bold text-yellow-600">-</p>
              </div>
            </div>
          </div>
          
          <div class="bg-gradient-to-r from-purple-900 to-purple-800 rounded-xl shadow-sm p-6 text-white">
            <h3 class="text-lg font-semibold mb-4">API 访问</h3>
            <div class="space-y-3">
              <div>
                <p class="text-sm opacity-80 mb-1">你的 API Token</p>
                <div class="bg-white/10 rounded-lg p-3">
                  <code id="apiToken" class="text-sm font-mono break-all cursor-pointer">点击显示</code>
                </div>
                <p class="text-xs opacity-60 mt-2">用于访问私有 API 接口</p>
              </div>
              
              <a href="/api/docs" target="_blank" class="block text-center bg-white/20 hover:bg-white/30 py-2 px-4 rounded-lg transition mt-4">
                <i class="fas fa-external-link-alt mr-2"></i>查看 API 文档
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    function logout() {
      document.cookie = 'token=; Path=/; Max-Age=0';
      window.location.href = '/dashboard/login';
    }
    
    function getCookie(name) {
      const value = \`; \${document.cookie}\`;
      const parts = value.split(\`; \${name}=\`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    }
    
    async function loadUserStats() {
      try {
        const token = getCookie('token');
        const response = await fetch('/api/contents/my', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.success) {
            const contents = data.data;
            document.getElementById('totalSubmissions').textContent = contents.length;
            document.getElementById('approvedSubmissions').textContent = contents.filter(c => c.status === 'approved').length;
            document.getElementById('pendingSubmissions').textContent = contents.filter(c => c.status === 'pending').length;
          }
        }
      } catch (error) {
        console.error('加载统计失败:', error);
      }
    }
    
    // 显示 API Token
    const tokenElement = document.getElementById('apiToken');
    tokenElement.addEventListener('click', () => {
      const token = getCookie('token');
      if (token) {
        tokenElement.textContent = token;
      }
    });
    
    // 修改密码
    document.getElementById('passwordForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const currentPassword = document.getElementById('currentPassword').value;
      const newPassword = document.getElementById('newPassword').value;
      const confirmNewPassword = document.getElementById('confirmNewPassword').value;
      const message = document.getElementById('passwordMessage');
      
      message.className = 'mt-4 hidden p-3 rounded-lg';
      message.textContent = '';
      
      if (newPassword !== confirmNewPassword) {
        message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
        message.textContent = '两次输入的密码不一致';
        return;
      }
      
      if (newPassword.length < 6) {
        message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
        message.textContent = '新密码长度不能少于6位';
        return;
      }
      
      try {
        const token = getCookie('token');
        const response = await fetch('/api/user/password', {
          method: 'PATCH',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ oldPassword: currentPassword, newPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
          message.className = 'mt-4 p-3 rounded-lg bg-green-100 text-green-700';
          message.textContent = data.message;
          document.getElementById('passwordForm').reset();
          
          setTimeout(() => {
            document.cookie = 'token=; Path=/; Max-Age=0';
            window.location.href = '/dashboard/login';
          }, 3000);
        } else {
          message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
          message.textContent = data.message;
        }
      } catch (error) {
        message.className = 'mt-4 p-3 rounded-lg bg-red-100 text-red-700';
        message.textContent = '修改失败：' + error.message;
      }
    });
    
    document.addEventListener('DOMContentLoaded', loadUserStats);
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function showAdminUsers(user, env) {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>用户管理 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .sidebar {
      background: linear-gradient(to bottom, #667eea, #764ba2);
    }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="flex">
    <div class="sidebar text-white w-64 min-h-screen p-6">
      <div class="mb-8">
        <h1 class="text-2xl font-bold">
          <i class="fas fa-film mr-2"></i>TMDB+
        </h1>
      </div>
      
      <nav class="space-y-2">
        <a href="/dashboard" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-home mr-3"></i>仪表板
        </a>
        <a href="/dashboard/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-photo-video mr-3"></i>我的提交
        </a>
        <a href="/dashboard/submit" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-plus-circle mr-3"></i>提交资料
        </a>
        <a href="/dashboard/profile" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-user-cog mr-3"></i>个人设置
        </a>
        
        <div class="mt-8 pt-6 border-t border-purple-700">
          <p class="px-4 text-sm text-purple-300 mb-3">管理</p>
          <a href="/dashboard/admin/users" class="block py-3 px-4 rounded-lg hover:bg-purple-700 bg-purple-700">
            <i class="fas fa-users mr-3"></i>用户管理
          </a>
          <a href="/dashboard/admin/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-tasks mr-3"></i>内容审核
          </a>
        </div>
        
        <div class="mt-8 pt-6 border-t border-purple-700">
          <a href="/" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-globe mr-3"></i>网站首页
          </a>
          <button onclick="logout()" class="block w-full text-left py-3 px-4 rounded-lg hover:bg-red-700">
            <i class="fas fa-sign-out-alt mr-3"></i>退出登录
          </button>
        </div>
      </nav>
    </div>
    
    <div class="flex-1 p-6">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">用户管理</h2>
      
      <div class="bg-white rounded-xl shadow-sm p-6">
        <div id="usersList" class="space-y-4">
          <div class="text-center py-8 text-gray-500">
            <i class="fas fa-spinner fa-spin text-2xl mb-2"></i>
            <p>加载中...</p>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    function logout() {
      document.cookie = 'token=; Path=/; Max-Age=0';
      window.location.href = '/dashboard/login';
    }
    
    function getCookie(name) {
      const value = \`; \${document.cookie}\`;
      const parts = value.split(\`; \${name}=\`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    }
    
    async function loadUsers() {
      try {
        const token = getCookie('token');
        const response = await fetch('/api/admin/users', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        const data = await response.json();
        const container = document.getElementById('usersList');
        
        if (data.success && data.data.length > 0) {
          container.innerHTML = \`
            <div class="overflow-x-auto">
              <table class="w-full">
                <thead class="bg-gray-50">
                  <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">用户</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">邮箱</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">角色</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">注册时间</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-200">
                  \${data.data.map(user => \`
                    <tr>
                      <td class="px-6 py-4">
                        <div class="flex items-center">
                          <div class="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center mr-3">
                            <i class="fas fa-user text-purple-600"></i>
                          </div>
                          <div>
                            <p class="font-medium">\${user.username}</p>
                            <p class="text-sm text-gray-500">ID: \${user.id}</p>
                          </div>
                        </div>
                      </td>
                      <td class="px-6 py-4">\${user.email}</td>
                      <td class="px-6 py-4">
                        <span class="px-2 py-1 text-xs rounded-full \${user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800'}">
                          \${user.role === 'admin' ? '管理员' : '普通用户'}
                        </span>
                      </td>
                      <td class="px-6 py-4 text-sm text-gray-500">
                        \${new Date(user.created_at).toLocaleDateString('zh-CN')}
                      </td>
                      <td class="px-6 py-4">
                        <div class="flex space-x-2">
                          \${user.id !== ${user.id} ? \`
                            <button onclick="changeRole(\${user.id}, '\${user.role}', '\${user.username}')" 
                              class="text-blue-600 hover:text-blue-800">
                              <i class="fas fa-user-edit"></i>
                            </button>
                            <button onclick="resetPassword(\${user.id}, '\${user.username}')" 
                              class="text-yellow-600 hover:text-yellow-800">
                              <i class="fas fa-key"></i>
                            </button>
                            <button onclick="deleteUser(\${user.id}, '\${user.username}')" 
                              class="text-red-600 hover:text-red-800">
                              <i class="fas fa-trash"></i>
                            </button>
                          \` : \`
                            <span class="text-gray-400">当前用户</span>
                          \`}
                        </div>
                      </td>
                    </tr>
                  \`).join('')}
                </tbody>
              </table>
            </div>
          \`;
        } else {
          container.innerHTML = \`
            <div class="text-center py-8">
              <i class="fas fa-users text-3xl text-gray-300 mb-2"></i>
              <p class="text-gray-500">暂无用户</p>
            </div>
          \`;
        }
      } catch (error) {
        container.innerHTML = \`
          <div class="text-center py-8 text-red-500">
            <i class="fas fa-exclamation-triangle text-2xl mb-2"></i>
            <p>加载失败：\${error.message}</p>
          </div>
        \`;
      }
    }
    
    async function changeRole(userId, currentRole, username) {
      const newRole = currentRole === 'admin' ? 'user' : 'admin';
      
      if (confirm(\`确定要将用户 "\${username}" 的角色修改为 "\${newRole === 'admin' ? '管理员' : '普通用户'}" 吗？\`)) {
        try {
          const token = getCookie('token');
          const response = await fetch(\`/api/admin/users/\${userId}/role\`, {
            method: 'PATCH',
            headers: {
              'Authorization': 'Bearer ' + token,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ role: newRole })
          });
          
          const data = await response.json();
          if (data.success) {
            alert(data.message);
            loadUsers();
          } else {
            alert('操作失败：' + data.message);
          }
        } catch (error) {
          alert('操作失败：' + error.message);
        }
      }
    }
    
    async function resetPassword(userId, username) {
      const newPassword = prompt(\`请输入用户 "\${username}" 的新密码（至少6位）：\`);
      
      if (newPassword && newPassword.length >= 6) {
        try {
          const token = getCookie('token');
          const response = await fetch(\`/api/admin/users/\${userId}/password\`, {
            method: 'PATCH',
            headers: {
              'Authorization': 'Bearer ' + token,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ newPassword })
          });
          
          const data = await response.json();
          if (data.success) {
            alert(data.message);
          } else {
            alert('重置失败：' + data.message);
          }
        } catch (error) {
          alert('重置失败：' + error.message);
        }
      } else if (newPassword) {
        alert('密码长度不能少于6位');
      }
    }
    
    async function deleteUser(userId, username) {
      if (confirm(\`确定要删除用户 "\${username}" 吗？此操作将删除该用户的所有提交，且不可恢复。\`)) {
        try {
          const token = getCookie('token');
          const response = await fetch(\`/api/admin/users/\${userId}\`, {
            method: 'DELETE',
            headers: { 'Authorization': 'Bearer ' + token }
          });
          
          const data = await response.json();
          if (data.success) {
            alert(data.message);
            loadUsers();
          } else {
            alert('删除失败：' + data.message);
          }
        } catch (error) {
          alert('删除失败：' + error.message);
        }
      }
    }
    
    document.addEventListener('DOMContentLoaded', loadUsers);
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function showAdminContents(user, env) {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>内容审核 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .sidebar {
      background: linear-gradient(to bottom, #667eea, #764ba2);
    }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="flex">
    <div class="sidebar text-white w-64 min-h-screen p-6">
      <div class="mb-8">
        <h1 class="text-2xl font-bold">
          <i class="fas fa-film mr-2"></i>TMDB+
        </h1>
      </div>
      
      <nav class="space-y-2">
        <a href="/dashboard" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-home mr-3"></i>仪表板
        </a>
        <a href="/dashboard/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-photo-video mr-3"></i>我的提交
        </a>
        <a href="/dashboard/submit" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-plus-circle mr-3"></i>提交资料
        </a>
        <a href="/dashboard/profile" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
          <i class="fas fa-user-cog mr-3"></i>个人设置
        </a>
        
        <div class="mt-8 pt-6 border-t border-purple-700">
          <p class="px-4 text-sm text-purple-300 mb-3">管理</p>
          <a href="/dashboard/admin/users" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-users mr-3"></i>用户管理
          </a>
          <a href="/dashboard/admin/contents" class="block py-3 px-4 rounded-lg hover:bg-purple-700 bg-purple-700">
            <i class="fas fa-tasks mr-3"></i>内容审核
          </a>
        </div>
        
        <div class="mt-8 pt-6 border-t border-purple-700">
          <a href="/" class="block py-3 px-4 rounded-lg hover:bg-purple-700">
            <i class="fas fa-globe mr-3"></i>网站首页
          </a>
          <button onclick="logout()" class="block w-full text-left py-3 px-4 rounded-lg hover:bg-red-700">
            <i class="fas fa-sign-out-alt mr-3"></i>退出登录
          </button>
        </div>
      </nav>
    </div>
    
    <div class="flex-1 p-6">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">内容审核</h2>
      
      <div class="bg-white rounded-xl shadow-sm p-6">
        <div id="contentsList" class="space-y-4">
          <div class="text-center py-8 text-gray-500">
            <i class="fas fa-spinner fa-spin text-2xl mb-2"></i>
            <p>加载中...</p>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    function logout() {
      document.cookie = 'token=; Path=/; Max-Age=0';
      window.location.href = '/dashboard/login';
    }
    
    function getCookie(name) {
      const value = \`; \${document.cookie}\`;
      const parts = value.split(\`; \${name}=\`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    }
    
    async function loadContents() {
      try {
        const token = getCookie('token');
        const response = await fetch('/api/admin/contents', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        const data = await response.json();
        const container = document.getElementById('contentsList');
        
        if (data.success && data.data.length > 0) {
          container.innerHTML = \`
            <div class="overflow-x-auto">
              <table class="w-full">
                <thead class="bg-gray-50">
                  <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">内容</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">提交者</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">状态</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-200">
                  \${data.data.map(item => \`
                    <tr>
                      <td class="px-6 py-4">
                        <div class="flex items-center">
                          \${item.poster_url ? \`
                            <img src="\${item.poster_url}" alt="\${item.title}" class="w-12 h-16 object-cover rounded mr-3">
                          \` : \`
                            <div class="w-12 h-16 bg-gray-200 rounded mr-3 flex items-center justify-center">
                              <i class="fas fa-film text-gray-400"></i>
                            </div>
                          \`}
                          <div>
                            <p class="font-medium">\${item.title}</p>
                            <p class="text-sm text-gray-500">\${item.type === 'movie' ? '电影' : '电视剧'}</p>
                          </div>
                        </div>
                      </td>
                      <td class="px-6 py-4">
                        <p class="font-medium">\${item.submitter_name || '未知用户'}</p>
                        <p class="text-sm text-gray-500">\${new Date(item.created_at).toLocaleDateString('zh-CN')}</p>
                      </td>
                      <td class="px-6 py-4">
                        <span class="px-2 py-1 text-xs rounded-full \${item.status === 'approved' ? 'bg-green-100 text-green-800' : item.status === 'rejected' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}">
                          \${item.status === 'approved' ? '已通过' : item.status === 'rejected' ? '已拒绝' : '待审核'}
                        </span>
                      </td>
                      <td class="px-6 py-4">
                        <div class="flex space-x-2">
                          \${item.status === 'pending' ? \`
                            <button onclick="approveContent(\${item.id}, '\${item.title}')" 
                              class="text-green-600 hover:text-green-800">
                              <i class="fas fa-check"></i>
                            </button>
                            <button onclick="rejectContent(\${item.id}, '\${item.title}')" 
                              class="text-red-600 hover:text-red-800">
                              <i class="fas fa-times"></i>
                            </button>
                          \` : ''}
                          <button onclick="deleteContent(\${item.id}, '\${item.title}')" 
                            class="text-gray-600 hover:text-gray-800">
                            <i class="fas fa-trash"></i>
                          </button>
                        </div>
                      </td>
                    </tr>
                  \`).join('')}
                </tbody>
              </table>
            </div>
          \`;
        } else {
          container.innerHTML = \`
            <div class="text-center py-8">
              <i class="fas fa-inbox text-3xl text-gray-300 mb-2"></i>
              <p class="text-gray-500">暂无待审核内容</p>
            </div>
          \`;
        }
      } catch (error) {
        container.innerHTML = \`
          <div class="text-center py-8 text-red-500">
            <i class="fas fa-exclamation-triangle text-2xl mb-2"></i>
            <p>加载失败：\${error.message}</p>
          </div>
        \`;
      }
    }
    
    async function approveContent(contentId, title) {
      if (confirm(\`确定要通过 "\${title}" 吗？\`)) {
        await updateContentStatus(contentId, 'approved', title);
      }
    }
    
    async function rejectContent(contentId, title) {
      const reason = prompt(\`请输入拒绝 "\${title}" 的理由：\`);
      if (reason !== null) {
        await updateContentStatus(contentId, 'rejected', title, reason);
      }
    }
    
    async function updateContentStatus(contentId, status, title, reason = '') {
      try {
        const token = getCookie('token');
        const response = await fetch(\`/api/admin/contents/\${contentId}/status\`, {
          method: 'PATCH',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ status, reason })
        });
        
        const data = await response.json();
        if (data.success) {
          alert(data.message);
          loadContents();
        } else {
          alert('操作失败：' + data.message);
        }
      } catch (error) {
        alert('操作失败：' + error.message);
      }
    }
    
    async function deleteContent(contentId, title) {
      if (confirm(\`确定要删除 "\${title}" 吗？此操作不可恢复。\`)) {
        try {
          const token = getCookie('token');
          const response = await fetch(\`/api/admin/contents/\${contentId}\`, {
            method: 'DELETE',
            headers: { 'Authorization': 'Bearer ' + token }
          });
          
          const data = await response.json();
          if (data.success) {
            alert(data.message);
            loadContents();
          } else {
            alert('删除失败：' + data.message);
          }
        } catch (error) {
          alert('删除失败：' + error.message);
        }
      }
    }
    
    document.addEventListener('DOMContentLoaded', loadContents);
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function showDashboard404() {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>404 - TMDB+</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center p-4">
  <div class="text-center">
    <h1 class="text-6xl font-bold text-purple-600 mb-4">404</h1>
    <h2 class="text-2xl font-semibold text-gray-800 mb-2">页面未找到</h2>
    <p class="text-gray-600 mb-8">您访问的页面不存在或已被移动。</p>
    <a href="/dashboard" class="inline-block bg-purple-600 hover:bg-purple-700 text-white px-6 py-3 rounded-lg font-semibold">
      返回仪表板
    </a>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    status: 404,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

// ==================== 首页处理 ====================
async function handleHome(request, env, ctx) {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TMDB+ - 让电影数据更伟大</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .hero-bg {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
  </style>
</head>
<body class="text-gray-800">
  <!-- 导航栏 -->
  <nav class="bg-white shadow-sm">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div class="flex justify-between h-16">
        <div class="flex items-center">
          <a href="/" class="flex items-center space-x-2">
            <i class="fas fa-film text-purple-600 text-2xl"></i>
            <span class="text-xl font-bold text-gray-900">TMDB+</span>
          </a>
        </div>
        
        <div class="flex items-center space-x-4">
          <a href="/api/docs" class="text-gray-700 hover:text-purple-600">API 文档</a>
          <a href="/api/contents/public" class="text-gray-700 hover:text-purple-600">资料库</a>
          <a href="/dashboard/login" class="text-gray-700 hover:text-purple-600">登录</a>
          <a href="/dashboard/register" class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg">
            免费注册
          </a>
        </div>
      </div>
    </div>
  </nav>
  
  <!-- 英雄区域 -->
  <header class="hero-bg text-white">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
      <div class="text-center">
        <h1 class="text-5xl font-bold mb-6">让电影数据更伟大</h1>
        <p class="text-xl mb-8 max-w-2xl mx-auto opacity-90">
          基于 TMDB 的开放影视资料平台，提供完整的 API 接口和用户友好的管理面板
        </p>
        <div class="flex flex-col sm:flex-row justify-center space-y-4 sm:space-y-0 sm:space-x-4">
          <a href="/dashboard" class="bg-white text-purple-600 hover:bg-gray-100 px-8 py-3 rounded-lg font-semibold text-lg">
            开始使用
          </a>
          <a href="/api/docs" class="bg-white/20 hover:bg-white/30 text-white px-8 py-3 rounded-lg font-semibold text-lg border border-white">
            API 文档
          </a>
        </div>
      </div>
    </div>
  </header>
  
  <!-- 特性介绍 -->
  <section class="py-20">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <h2 class="text-3xl font-bold text-center mb-12">为什么选择 TMDB+？</h2>
      
      <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
        <div class="bg-white p-8 rounded-xl shadow-sm border border-gray-100">
          <div class="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-6">
            <i class="fas fa-bolt text-purple-600 text-xl"></i>
          </div>
          <h3 class="text-xl font-semibold mb-4">完全开放的 API</h3>
          <p class="text-gray-600">
            提供完整的 RESTful API，无需登录即可访问公开数据，支持开发者集成使用。
          </p>
        </div>
        
        <div class="bg-white p-8 rounded-xl shadow-sm border border-gray-100">
          <div class="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-6">
            <i class="fas fa-tv text-blue-600 text-xl"></i>
          </div>
          <h3 class="text-xl font-semibold mb-4">TMDB 数据集成</h3>
          <p class="text-gray-600">
            无缝对接 TMDB 数据库，自动补全电影、电视剧信息，支持自定义字段扩展。
          </p>
        </div>
        
        <div class="bg-white p-8 rounded-xl shadow-sm border border-gray-100">
          <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-6">
            <i class="fas fa-users-cog text-green-600 text-xl"></i>
          </div>
          <h3 class="text-xl font-semibold mb-4">友好管理面板</h3>
          <p class="text-gray-600">
            现代化的响应式管理界面，支持用户提交、管理员审核、统计报表等功能。
          </p>
        </div>
      </div>
    </div>
  </section>
  
  <!-- API 演示 -->
  <section class="py-20 bg-gray-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div class="text-center mb-12">
        <h2 class="text-3xl font-bold mb-4">立即体验 API</h2>
        <p class="text-gray-600 max-w-2xl mx-auto">以下接口无需认证即可调用</p>
      </div>
      
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div class="bg-white rounded-xl shadow-sm p-6">
          <h3 class="text-lg font-semibold mb-4">搜索电影示例</h3>
          <div class="bg-gray-900 text-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
            <pre><code>fetch('/api/tmdb/search?query=avatar&type=movie')
  .then(res => res.json())
  .then(data => console.log(data));</code></pre>
          </div>
          <button onclick="testSearch()" class="mt-4 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg">
            在线测试
          </button>
        </div>
        
        <div class="bg-white rounded-xl shadow-sm p-6">
          <h3 class="text-lg font-semibold mb-4">查看公开资料</h3>
          <div class="bg-gray-900 text-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
            <pre><code>fetch('/api/contents/public?page=1&limit=10')
  .then(res => res.json())
  .then(data => console.log(data));</code></pre>
          </div>
          <button onclick="testPublic()" class="mt-4 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg">
            在线测试
          </button>
        </div>
      </div>
      
      <div id="apiResult" class="mt-8 bg-white rounded-xl shadow-sm p-6 hidden">
        <h4 class="font-semibold mb-2">API 响应：</h4>
        <pre class="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm" id="resultContent"></pre>
      </div>
    </div>
  </section>
  
  <!-- 底部 -->
  <footer class="bg-gray-900 text-white py-12">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div class="text-center">
        <div class="flex justify-center mb-6">
          <i class="fas fa-film text-3xl text-purple-400"></i>
          <span class="text-2xl font-bold ml-2">TMDB+</span>
        </div>
        <p class="text-gray-400 mb-6">基于 Cloudflare Workers 构建的开源影视资料平台</p>
        <div class="flex flex-col sm:flex-row justify-center space-y-4 sm:space-y-0 sm:space-x-8">
          <a href="/api" class="text-gray-300 hover:text-white">API 首页</a>
          <a href="/api/docs" class="text-gray-300 hover:text-white">API 文档</a>
          <a href="/dashboard/login" class="text-gray-300 hover:text-white">用户登录</a>
          <a href="/dashboard/register" class="text-gray-300 hover:text-white">免费注册</a>
        </div>
        <p class="text-gray-500 text-sm mt-8">© 2024 TMDB+ 平台 | 数据来自 TMDB API</p>
      </div>
    </div>
  </footer>
  
  <script>
    async function testSearch() {
      const resultDiv = document.getElementById('apiResult');
      const content = document.getElementById('resultContent');
      
      resultDiv.classList.remove('hidden');
      content.textContent = '请求中...';
      
      try {
        const response = await fetch('/api/tmdb/search?query=avatar&type=movie');
        const data = await response.json();
        content.textContent = JSON.stringify(data, null, 2);
      } catch (error) {
        content.textContent = '错误: ' + error.message;
      }
    }
    
    async function testPublic() {
      const resultDiv = document.getElementById('apiResult');
      const content = document.getElementById('resultContent');
      
      resultDiv.classList.remove('hidden');
      content.textContent = '请求中...';
      
      try {
        const response = await fetch('/api/contents/public?page=1&limit=5');
        const data = await response.json();
        content.textContent = JSON.stringify(data, null, 2);
      } catch (error) {
        content.textContent = '错误: ' + error.message;
      }
    }
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

// ==================== 辅助函数 ====================
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}
