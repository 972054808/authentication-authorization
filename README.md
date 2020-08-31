# 认证与授权

### 认证(authentication)

+ 核心目的
    + 认证访问者是谁
    + 我是谁
+ 指的是当前用户的身份，当用户登陆过后系统便能追踪到他的身份做出符合相应业务逻辑的操作。即使用户没有登录，大多数系统也会追踪他的身份，只是当做来宾或者匿名用户来处理。认证技术解决的是 “我是谁？”的问题。

### 授权(authorization)

+ 核心目的
    + 访问权限
    + 我能做什么
+ 指的是什么样的身份被允许访问某些资源，在获取到用户身份后继续检查用户的权限

## 常见的认证机制

### HTTP基本认证(HTTP Basic Auth)

在HTTP中，HTTP基本认证是一种允许Web浏览器或者其他客户端在请求时提供用户名和口令形式的身份凭证的一种登陆验证方式。

**优点**

+ 实现简单，使用的是HTTP头部字段强制用户访问网络资源，而非采取获取访问控制的手段

+ 基本所有流行的网页浏览器都支持

**缺点**

+ 没有为传送凭证提供任何机密性保护
+ 由于现存的浏览器保存认证信息直到标签页、浏览器关闭或者用户主动清除历史记录。导致了服务器端无法主动登出或者认证失效
+ HTTP并没有提供登出机制

**用途**

+ 小型私有系统
    + 路由器网页管理接口
+ 可信网络环境

**过程**

+ 客户端请求一个需要身份认证的页面
+ 服务端返回一个401状态码，并提供一个认证域，头部字段为：`WWW-Authenticate`，该字段为要求客户端提供适配的资源
+ 接到应答后，客户端显示该认证域给用户并提示输入用户名和口令。此时用户可以选择确定或取消
+ 用户输入了用户名和口令后，客户端将对其进行处理，并在原先的请求上增加认证消息头然后重新发送请求。具体处理过程如下
    + 将用户名和口令拼接为用户：密码形式的字符串
    + 如果服务器`WWW-Authenticate`字段有指定编码，则将字符串编译成对应的编码（如：UTF-8）
    + 将字符串编码为base64
    + 拼接`Basic` ，放入`Authorization`头字段，就像这样：`Authorization Basic 字符串`。 示例：用户名：`Aladdin` ，密码：`OpenSesame` ，拼接后为`Aladdin:OpenSesame`，编码后`QWxhZGRpbjpPcGVuU2VzYW1l`，在HTTP头部里会是这样：`Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l`。 Base64编码并非加密算法，其无法保证安全与隐私，仅用于将用户名和密码中的不兼容的字符转换为均与HTTP协议兼容的字符集
+ 服务端接受该认证后，如果认证成功则返回请求页面。如果用户凭据非法或无效，服务器可能再次返回401状态码，客户端可以再次提示用户输入密码






### OAuth2.0认证

OAuth 2.0 是目前最流行的授权机制，用来授权第三方应用，获取用户数据。所以其最常见的应用场景就是第三方登录。

**优点**

+ 客户端不接触用户密码
+ 支持短寿命和封装的Token
+ 资源服务器和授权服务器解耦
+ 集中式授权，简化客户端
+ 客户端可以具有不同的信任级别

**缺点**

+ 协议框架太宽泛，造成各种实现的兼容性和互操作性差
+ 和OAuth1.0不兼容

#### OAuth2.0的认证流程

**角色**

+ resource owner 资源所有者，能够允许访问受保护资源的实体。如果是个人，被称为 end-user
+ resource server 资源服务器，托管受保护资源的服务器
+ client 客户端，使用资源所有者的授权代表资源所有者发起对受保护资源的请求的应用程序
    + web网站、移动app等
+ authorization server 授权服务器，能够向客户端颁发令牌
+ user-agent，用户代理帮，助资源所有者与客户端沟通的工具
    + 一般为web浏览器、移动app等

**流程图**

![oauth2-roles](https://st.deepzz.com/blog/img/oauth2-roles.jpg)

+ A Client 请求 Resource Owner 的授权。授权请求可以直接向 Resource Owner 请求，也可以通过 Authorization Server 间接的进
+ B Client 获得授权许可
+ C Client 向 Authorization Server 请求访问令牌
+ D Authorization Server 验证授权许可，如果有效则颁发访问令牌。
+ E Client 通过访问令牌从 Resource Server 请求受保护资源
+ F Resource Server 验证访问令牌，有效则响应请求

**授权类型**

OAuth 2.0 列举了四种授权类型，分别用于不同的场景

+ Authorization Code（授权码 code）：服务器与客户端配合使用
+ Implicit（隐式 token）：用于移动应用程序或 Web 应用程序（在用户设备上运行的应用程序）
+ Resource Owner Password Credentials（资源所有者密码凭证 password）：资源所有者和客户端之间具有高度信任时（例如，客户端是设备的操作系统的一部分，或者是一个高度特权应用程序），以及当其他授权许可类型（例如授权码）不可用时被使用
+ Client Credentials（客户端证书 client_credentials）：当客户端代表自己表演（客户端也是资源所有者）或者基于与授权服务器事先商定的授权请求对受保护资源的访问权限时，客户端凭据被用作为授权许可

**授权码模式**

该方式需要资源服务器的参与，应用场景大概是

+ 资源拥有者（用户）需要登录客户端（APP），他选择了第三方登录。
+ 客户端（APP）重定向到第三方授权服务器。此时客户端携带了客户端标识（client_id），那么第三方就知道这是哪个客户端，资源拥有者确定（拒绝）授权后需要重定向到哪里
+ 用户确认授权，客户端（APP）被重定向到注册时给定的 URI，并携带了第三方给定的 code
+ 在重定向的过程中，客户端拿到 code 与 `client_id`、`client_secret` 去授权服务器请求令牌，如果成功，直接请求资源服务器获取资源，整个过程，用户代理是不会拿到令牌 token 的
+ 客户端（APP）拿到令牌 token 后就可以向第三方的资源服务器请求资源了


**隐式模式**

该方式一般用于移动客户端或网页客户端。隐式授权类似于授权码授权，但 token 被返回给用户代理再转发到客户端（APP），因此它可能会暴露给用户和用户设备上的其它客户端（APP）。此外，此流程不会对客户端（APP）的身份进行身份验证，并且依赖重定向 URI（已在服务商中注册）来实现此目的。

基本原理：要求用户授权应用程序，然后授权服务器将访问令牌传回给用户代理，用户代理将其传递给客户端。

**资源所有者密码模式**

用户将其服务凭证（用户名和密码）直接提供给客户端，该客户端使用凭据从服务获取访问令牌。如果其它方式不可行，则只应在授权服务器上启用该授权类型。此外，只有在客户端受到用户信任时才能使用它（例如，它由服务商自有，或用户的桌面操作系统）。

**客户端模式**

这种模式只需要提供 `client_id` 和 `client_secret` 即可获取授权。一般用于后端 API 的相关操作。





### **JWT**（JSON Web Token）

JWT是一种用于双方之间传递安全信息的简洁的、URL安全的表述性声明规范。JWT作为一个开放的标准（RFC 7519），定义了一种简洁的，自包含的方法用于通信双方之间以Json对象的形式安全的传递信息。因为数字签名的存在，这些信息是可信的，JWT**可以使用HMAC算法或者是RSA的公私秘钥**对进行签名。

**优点**

+ **简洁(Compact)**: 可以通过URL，POST参数或者在HTTP header发送，因为数据量小，传输速度也很快
+ **自包含(Self-contained)**：负载中包含了所有用户所需要的信息，避免了多次查询数据库

**缺点**

+ 由于服务器不保存 session 状态，因此无法在使用过程中废止某个 token，或者更改 token 的权限
+ JWT 本身包含了认证信息，一旦泄露，任何人都可以获得该令牌的所有权限

**原理**

JWT 的原理是，服务器认证以后，生成一个 JSON 对象，发回给用户，就像下面这样。

```json
{
  "姓名": "张三",
  "权限": "管理员",
  "到期时间": "2018年7月1日0点0分"
}
```

以后，用户与服务端通信的时候，都要发回这个 JSON 对象。服务器完全只靠这个对象认定用户身份。为了防止用户篡改数据，服务器在生成这个对象的时候，会加上签名

服务器就不保存任何 session 数据了，也就是说，服务器变成无状态了，从而比较容易实现扩展。

**JWT的数据结构**

JWT的组成

+ Header（头部）

    + Header 部分是一个 JSON 对象，描述 JWT 的元数据，通常是下面的样子。

        ```
        {
          "alg": "HS256",
          "typ": "JWT"
        }
        ```

    + 上面代码中，`alg`属性表示签名的算法（algorithm），默认是 HMAC SHA256（写成 HS256）；`typ`属性表示这个令牌（token）的类型（type），JWT 令牌统一写为`JWT`

+ Payload（负载）

    + Payload 部分也是一个 JSON 对象，用来存放实际需要传递的数据。JWT 规定了7个官方字段，供选用。

        + iss (issuer)：签发人
        + exp (expiration time)：过期时间
        + sub (subject)：主题
        + aud (audience)：受众
        + nbf (Not Before)：生效时间
        + iat (Issued At)：签发时间
        + jti (JWT ID)：编号

    + 除了官方字段，你还可以在这个部分定义私有字段，下面就是一个例子。

        ```
        {
          "sub": "1234567890",
          "name": "John Doe",
          "admin": true
        }
        ```

    + 注意，JWT 默认是不加密的，任何人都可以读到，所以不要把秘密信息放在这个部分。

+ Signature（签名）

    + Signature 部分是对前两部分的签名，防止数据篡改。

    + 首先，需要指定一个密钥（secret）。这个密钥只有服务器才知道，不能泄露给用户。然后，使用 Header 里面指定的签名算法（默认是 HMAC SHA256），按照下面的公式产生签名。

        ```
        HMACSHA256(
          base64UrlEncode(header) + "." +
          base64UrlEncode(payload),
          secret)
        ```

    + 算出签名以后，把 Header、Payload、Signature 三个部分拼成一个字符串，每个部分之间用"点"（`.`）分隔，就可以返回给用户。

**JWT特点**

+ JWT 默认是不加密，但也是可以加密的。生成原始 Token 以后，可以用密钥再加密一次。
+ JWT 不加密的情况下，不能将秘密数据写入 JWT。
+ JWT 本身包含了认证信息，一旦泄露，任何人都可以获得该令牌的所有权限。为了减少盗用，JWT 的有效期应该设置得比较短。对于一些比较重要的权限，使用时应该再次对用户进行认证。
+ 为了减少盗用，JWT 不应该使用 HTTP 协议明码传输，要使用 HTTPS 协议传输。



### **OpenID**

OpenID Connect遵循oAuth2.0协议流程，并在这个基础上提供了id token来解决三方应用的用户身份认证问题

**优点**

+ 容易处理的id token。OpenID Connect使用JWT来给应用传递用户的身份信息。JWT以其高安全性（防止token被伪造和篡改）、跨语言、支持过期、自包含等特性而著称，非常适合作为token来使
+ 基于oAuth2.0协议。id token是经过oAuth2.0流程来获取的，这个流程即支持web应用，也支持原生app
+ 简单。OpenID Connect足够简单。但同时也提供了大量的功能和安全选项以满足企业级业务需求。

**角色**

+ **EU**：End User，用户。

+ **RP**：Relying Party ，用来代指*OAuth2*中的受信任的客户端，身份认证和授权信息的消费方；

+ **OP**：OpenID Provider，有能力提供EU身份认证的服务方（比如*OAuth2*中的授权服务），用来为RP提供EU的身份认证信息；

+ **ID-Token**：JWT格式的数据，包含EU身份认证的信息。

    + **iss = Issuer Identifier**：必须。提供认证信息者的唯一标识。一般是Url的host+path部分；

    + **sub = Subject Identifier**：必须。iss提供的EU的唯一标识；最长为255个ASCII个字符；

    + **aud = Audience(s)**：必须。标识*ID-Token*的受众。必须包含*OAuth2*的client_id；

    + **exp = Expiration time**：必须。*ID-Token*的过期时间；

    + **iat = Issued At Time**：必须。JWT的构建的时间。

    + **auth_time = AuthenticationTime**：EU完成认证的时间。如果RP发送认证请求的时候携带*max_age*的参数，则此Claim是必须的。

    + **nonce**：RP发送请求的时候提供的随机字符串，用来减缓重放攻击，也可以来关联*ID-Token*和RP本身的Session信息。

    + **acr = Authentication Context Class Reference**：可选。表示一个认证上下文引用值，可以用来标识认证上下文类。

    + **amr = Authentication Methods References**：可选。表示一组认证方法。

    + **azp = Authorized party**：可选。结合aud使用。只有在被认证的一方和受众（aud）不一致时才使用此值，一般情况下很少使用

        ```
        {
           "iss": "https://server.example.com",
           "sub": "24400320",
           "aud": "s6BhdRkqt3",
           "nonce": "n-0S6_WzA2Mj",
           "exp": 1311281970,
           "iat": 1311280970,
           "auth_time": 1311280969,
           "acr": "urn:mace:incommon:iap:silver"
          }
        ```

+ **UserInfo Endpoint**：用户信息接口（受*OAuth2*保护），当RP使用*ID-Token*访问时，返回授权用户的信息，此接口必须使用*HTTPS*。

**三种实现模式**

+ 如果是传统的客户端应用，后端代码和用户是隔离的，能保证*client_secret*的不被泄露，就可以使用**授权码模式流程**（Authentication Flow）。
+ 如果是JS应用，其所有的代码都会被加载到浏览器而暴露出来，没有后端可以保证*client_secret*的安全性，则需要是使用**默认模式流程**(Implicit Flow)。
+ **混合模式流程**(Hybrid Flow）上面两种模式等融合

**授权码模式流程**

+ RP发送一个认证请求给OP，其中附带*client_id*；
+ OP对EU进行身份认证；
+ OP返回响应，发送授权码给RP；
+ RP使用授权码向OP索要ID-Token和Access-Token，RP验证无误后返回给RP；
+ RP使用Access-Token发送一个请求到*UserInfo EndPoint*； UserInfo EndPoint返回EU的Claims。

**默认模式**

+ 默认流程和*OAuth*中的类似，只不过也是添加了*ID-Token*的相关内容。
+ *OIDC*的说明文档里很明确的说明了用户的相关信息都要使用**JWT**形式编码。在*JWT*中，不应该在载荷里面加入任何敏感的数据。如果传输的是用户的User ID。这个值实际上不是什么敏感内容，一般情况下被知道也是安全的。
+ 现在工业界已经**不推荐**使用*OAuth*默认模式，而推荐使用不带*client_Secret*的*授权码模式*。
