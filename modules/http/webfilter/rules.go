package webfilter

// builtinRules is the built-in fingerprint rule set, ported 1:1 from the
// standalone web_filter.py tool. Rules are evaluated in order and the first
// match wins, so keep the proxy/waf rules that identify the most specific
// signals ahead of the more generic ones (the order mirrors web_filter.py).
//
// Pattern semantics (identical to web_filter.py):
//   - status: the response status code must be one of the listed codes
//   - headers: any listed header must exist and match its regex ("*" = the
//     header's presence alone is enough); header names are lower-case
//   - title: any regex must match the normalized <title> content
//   - body:   any regex must match the (charset-decoded) body text
//   - match=any (default): one group hit is enough; match=all: every
//     non-empty group must hit
//
// All patterns are case-insensitive.
var builtinRules = []Rule{
	// ---------------- proxy: 需认证/开放 HTTP 代理 ----------------
	{
		Name:     "http_407",
		Category: CategoryProxy,
		Reason:   "HTTP 407 需代理认证",
		Status:   []int{407},
	},
	{
		Name:     "proxy_auth_header",
		Category: CategoryProxy,
		Reason:   "Proxy-Authenticate 代理认证头",
		Headers:  map[string]string{"proxy-authenticate": "*"},
	},
	{
		Name:     "squid_proxy",
		Category: CategoryProxy,
		Reason:   "Squid 代理提示页",
		Headers: map[string]string{
			"server":        "squid",
			"via":           "squid",
			"x-squid-error": ".",
		},
		Body: []string{
			"cache access denied",
			"by squid",
			`squid/[0-9]`,
			"access control configuration prevents",
		},
	},
	{
		Name:     "small_http_proxy",
		Category: CategoryProxy,
		Reason:   "Tinyproxy/Privoxy/3proxy 代理服务",
		Headers: map[string]string{
			"server": `\b(?:tinyproxy|privoxy|3proxy|mitmproxy)\b`,
		},
		Body: []string{"tinyproxy", "privoxy is running", "3proxy"},
	},
	{
		Name:     "proxy_error_page",
		Category: CategoryProxy,
		Reason:   "代理错误/认证提示页",
		Title:    []string{"proxy authentication required", "proxy error"},
		Body: []string{
			"the requested url could not be retrieved",
			"proxy authentication required",
			"连接到代理服务器失败",
			"proxy denies access",
		},
	},

	// ---------------- cdn: CDN 节点/提示页 ----------------
	{
		Name:     "cloudflare",
		Category: CategoryCDN,
		Reason:   "Cloudflare CDN/WAF 边缘节点",
		Headers: map[string]string{
			"cf-ray": ".",
			"server": "^cloudflare",
		},
		Body: []string{
			`attention required!\s*\|\s*cloudflare`,
			"checking your browser before accessing",
			"sorry, you have been blocked",
			"ray id:",
			"cloudflare-nginx",
			"direct ip access not allowed",
			`error 52[0-9]\b`,
		},
	},
	{
		Name:     "cloudfront",
		Category: CategoryCDN,
		Reason:   "AWS CloudFront 节点",
		Headers: map[string]string{
			"x-amz-cf-id": ".",
			"x-cache":     "cloudfront",
		},
		Body: []string{
			`we can'?t connect to the server for this app or website`,
			"the request could not be satisfied",
			"cloudfront",
		},
	},
	{
		Name:     "fastly",
		Category: CategoryCDN,
		Reason:   "Fastly CDN 节点",
		Headers:  map[string]string{"x-served-by": "^cache-"},
		Body:     []string{"fastly error: unknown domain", "unknown domain: fastly"},
	},
	{
		Name:     "akamai",
		Category: CategoryCDN,
		Reason:   "Akamai 边缘节点",
		Headers:  map[string]string{"server": "akamai"},
		Body:     []string{"akamaighost", "akamai edge"},
	},
	{
		Name:     "cn_cdn",
		Category: CategoryCDN,
		Reason:   "CDN 厂商提示/默认页",
		Body: []string{
			"百度云加速", "腾讯云CDN", "又拍云", `upyun\.com`,
			"七牛云", `qbox\.me`, "qiniudns", "网宿科技", "chinacache",
			`wangsu\.com`, "edgeone", "CDN默认页", "CDN提示页",
			"CDN未配置", "CDN未接入", "CDN加速节点",
		},
	},
	{
		Name:     "cdn_no_domain",
		Category: CategoryCDN,
		Reason:   "CDN/域名未配置提示页",
		Title:    []string{"域名未配置", "未绑定域名", "pending domain", "welcome to cdn"},
		Body: []string{
			`domain (?:is )?not (?:yet )?configured`,
			`no (?:domain|origin|site) (?:is )?configured`,
			`origin (?:is )?not configured`,
			"源站配置错误",
			`please configure a (?:domain|origin) name`,
			"this domain is parked",
		},
	},

	// ---------------- waf: 云 WAF/防护拦截页 ----------------
	{
		Name:     "aliyun_waf",
		Category: CategoryWAF,
		Reason:   "阿里云WAF/云盾拦截页",
		Body: []string{
			`errors\.aliyun\.com`,
			"Web应用防火墙",
			"您的请求可能对网站造成威胁",
			`(?:captcha|punish)\.aliyun`,
			`request blocked.*aliyun`,
		},
	},
	{
		Name:     "tencent_waf",
		Category: CategoryWAF,
		Reason:   "腾讯云WAF拦截页",
		Body: []string{
			`waf\.tencentcloud`,
			"腾讯云WAF",
			"腾讯云防火墙",
			"您的请求被WAF",
		},
	},
	{
		Name:     "chuangyu_yunsuo",
		Category: CategoryWAF,
		Reason:   "创宇盾/云锁防护页",
		Headers:  map[string]string{"set-cookie": "yunsuo"},
		Body:     []string{"创宇盾", "yunsuo", "knownsec", "云锁"},
	},
	{
		Name:     "safedog",
		Category: CategoryWAF,
		Reason:   "安全狗WAF",
		Headers: map[string]string{
			"server":       "safedog",
			"x-powered-by": "safedog",
		},
		Body: []string{"safedog", "安全狗", "网站安全狗"},
	},
	{
		Name:     "safeline",
		Category: CategoryWAF,
		Reason:   "长亭雷池WAF",
		Body:     []string{"safeline", "雷池WAF", "雷池"},
	},
	{
		Name:     "anquanbao",
		Category: CategoryWAF,
		Reason:   "安全宝防护",
		Body:     []string{"anquanbao", "安全宝"},
	},
	{
		Name:     "wzb_360",
		Category: CategoryWAF,
		Reason:   "360网站卫士",
		Body:     []string{"网站卫士", "360wzb"},
	},
	{
		Name:     "modsecurity",
		Category: CategoryWAF,
		Reason:   "ModSecurity WAF",
		Headers:  map[string]string{"server": "mod_security"},
		Body:     []string{"modsecurity", "mod_security"},
	},
	{
		Name:     "f5_asm",
		Category: CategoryWAF,
		Reason:   "F5 ASM/WAF拦截页",
		Body:     []string{"the requested url was rejected", "your support id is:", "trafficshield", "F5 BIG-IP"},
	},
	{
		Name:     "incapsula",
		Category: CategoryWAF,
		Reason:   "Imperva Incapsula WAF",
		Headers: map[string]string{
			"x-iinfo": ".",
			"x-cdn":   "incapsula",
		},
		Body: []string{"incapsula", "_incapsula_resource", "visid_incap"},
	},
	{
		Name:     "aws_waf",
		Category: CategoryWAF,
		Reason:   "AWS WAF 拦截页",
		Title:    []string{"request blocked"},
		Body:     []string{`request blocked\.`, "awswaf"},
	},
	{
		Name:     "bluedon",
		Category: CategoryWAF,
		Reason:   "蓝盾WAF",
		Body:     []string{"bluedon", "蓝盾WAF", "bdwaf"},
	},
	{
		Name:     "nsfocus_waf",
		Category: CategoryWAF,
		Reason:   "绿盟WAF",
		Body:     []string{"nsfocus", "绿盟WAF"},
	},
	{
		Name:     "anheng_waf",
		Category: CategoryWAF,
		Reason:   "安恒明御WAF",
		Body:     []string{"明御Web应用防火墙", "dbappsecurity", "anheng waf"},
	},
	{
		Name:     "generic_waf_block",
		Category: CategoryWAF,
		Reason:   "通用WAF拦截/人机验证页",
		Title:    []string{"请求被拦截", `access denied.*waf`, "安全验证", "人机验证"},
		Body: []string{
			`请求(?:被)?(?:已)?拦截`,
			"waf拦截", "防火墙拦截",
			"安全策略拦截", "防护规则拦截",
			"疑似攻击行为", "检测到攻击行为",
			"请完成以下验证后继续访问", "请验证后继续访问",
			"人机验证", "风控拦截", "触发安全防护",
		},
	},

	// ---------------- default: 中间件/默认页 ----------------
	{
		Name:     "nginx_default",
		Category: CategoryDefault,
		Reason:   "Nginx 默认页",
		Title:    []string{"welcome to nginx", "welcome to tengine"},
		Body:     []string{"welcome to nginx", "welcome to tengine"},
	},
	{
		Name:     "apache_default",
		Category: CategoryDefault,
		Reason:   "Apache 默认页",
		Title: []string{
			`^\s*it works!?\s*$`,
			"apache2 (?:ubuntu|debian) default page",
			"apache http server test page",
			"test page for the",
		},
		Body: []string{
			`<h1[^>]*>\s*it works!?`,
			"apache2 (?:ubuntu|debian) default page",
			"apache http server test page",
			"test page for the (?:nginx|http) server",
		},
	},
	{
		Name:     "iis_default",
		Category: CategoryDefault,
		Reason:   "IIS 默认页",
		Title:    []string{"iis windows", `^\s*iis[0-9]?\s*$`},
		Body:     []string{"internet information services", "Internet 信息服务"},
	},
	{
		Name:     "tomcat_default",
		Category: CategoryDefault,
		Reason:   "Tomcat 默认页",
		Title:    []string{"apache tomcat"},
		Body:     []string{"successfully installed tomcat", `if you'?re seeing this page`},
	},
	{
		Name:     "openresty_default",
		Category: CategoryDefault,
		Reason:   "OpenResty 默认页",
		Title:    []string{"welcome to openresty"},
	},
	{
		Name:     "dir_index",
		Category: CategoryDefault,
		Reason:   "目录索引页(Index of /)",
		Title:    []string{`^index of /?`},
	},
	{
		Name:     "placeholder_page",
		Category: CategoryDefault,
		Reason:   "主机商占位/默认页",
		Title: []string{
			"default web site page", "placeholder page", "default web page",
			`web server'?s default page`,
		},
	},

	// ------- panel: 管理面板(默认保留, --web-filter-drop panel 启用) -------
	{
		Name:     "bt_panel",
		Category: CategoryPanel,
		Reason:   "宝塔主机面板",
		Title:    []string{"宝塔Linux面板", "宝塔面板", "BT-Panel"},
		Body: []string{
			"宝塔面板", "宝塔Linux面板", "宝塔Windows面板", "BT-Panel",
			"btpanel", "宝塔面板登录",
		},
	},
	{
		Name:     "db_admin_panel",
		Category: CategoryPanel,
		Reason:   "数据库管理面板",
		Title:    []string{"phpmyadmin", "adminer"},
		Body:     []string{"phpmyadmin", "adminer"},
	},
	{
		Name:     "bastion_panel",
		Category: CategoryPanel,
		Reason:   "堡垒机/运维面板",
		Body:     []string{"jumpserver", "堡垒机", "齐治堡垒"},
	},
	{
		Name:     "hw_mgmt_panel",
		Category: CategoryPanel,
		Reason:   "服务器带外管理(iDRAC/IPMI)",
		Body: []string{
			"idrac", "integrated dell remote access", `ilo[ :/0-9]`, `\bipmi\b`,
			"supermicro", "BMC管理", "kvm over ip",
		},
	},
	{
		Name:     "hosting_panel",
		Category: CategoryPanel,
		Reason:   "主机/虚拟化面板",
		Body: []string{
			"webmin", "solusvm", "virtualizor", `\bwdcp\b`, `\bamh\b`,
			"虚拟主机管理平台",
		},
	},

	// ------- device: 设备/VPN(默认保留, --web-filter-drop device 启用) -------
	{
		Name:     "ssl_vpn",
		Category: CategoryDevice,
		Reason:   "SSL VPN/远程接入入口",
		Title:    []string{"ssl vpn", "easyconnect", "SSL VPN"},
		Body: []string{
			`ssl\s?vpn`, "easyconnect", "aTrust", "sangfor", "深信服",
			"fortigate", "fortinet", "forticlient", "pulse secure",
			"juniper networks", "array networks", "anyconnect",
			"F5 BIG-IP", "远程接入门户",
		},
	},
	{
		Name:     "netdevice",
		Category: CategoryDevice,
		Reason:   "网络设备管理页",
		Title: []string{
			"tp-link", "mikrotik", "routeros", "h3c", "d-link",
			"netgear", "sonicwall", "ruijie networks",
		},
		Body: []string{
			`tp-?link`, "mikrotik", "routeros", `\bh3c\b`, `d-link`,
			"netgear", "sonicwall", "huawei technologies",
			"Huawei Technologies Co., Ltd.", "aruba networks",
			"ruijie networks",
		},
	},
	{
		Name:     "camera_dvr",
		Category: CategoryDevice,
		Reason:   "摄像头/监控设备",
		Body: []string{
			"hikvision", "Hikvision Digital Technology", "dahua", "Dahua",
			"网络摄像机", `\bip camera\b`, "axis communications", "webcam",
		},
	},
	{
		Name:     "printer",
		Category: CategoryDevice,
		Reason:   "打印机设备",
		Body:     []string{"hp laserjet", "canon imagerunner", "ricoh", "xerox", "epson web", "打印机"},
	},
	{
		Name:     "wifi_portal",
		Category: CategoryDevice,
		Reason:   "Wi-Fi/Portal 认证页",
		Body: []string{
			`\bcmcc\b`, "WLAN认证", "Portal认证", "上网认证",
			"认证门户", "运营商认证",
		},
	},
}
