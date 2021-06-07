## Spring Secutiry 笔记

### 一，引入依赖

#### 1.1 Spring Boot with Maven

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
</dependencies>
```

**单独升级spring-security版本**

```xml
<properties>
    <spring-security.version>5.2.8.RELEASE</spring-security.version>
</dependencies>


<properties>
    <!-- 升级spring版本 -->
    <spring.version>5.2.11.RELEASE</spring.version>
</dependencies>
```



#### 1.2 Maven without Spring Boot

```xml
<dependencyManagement>
    <dependencies>
        <!-- ... other dependency elements ... -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-bom</artifactId>
            <version>5.2.8.RELEASE</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```



### 二，站点保护

#### 2.1 CSRF

跨站攻击：攻击者利用隐藏的表单提交给目标网站，如果当前用户在浏览器登陆这个网站没有退出，就会有又可能受到攻击

##### 2.1.1 Synchronizer Token request

在用户登录成功后，后端生成随机字符串存放在session中，前端每一次请求都将该字符串放入请求体或请求头中，后端进行合法验证。

##### 2.1.2 SameSite Attribute



### 三，技术概览

#### 3.1 核心组件

##### 3.1.1 SecurityContextHolder, SecurityContext and Authentication Objects

**三种用户上下文存储策略**

```java
public static final String MODE_THREADLOCAL = "MODE_THREADLOCAL";
public static final String MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL";
public static final String MODE_GLOBAL = "MODE_GLOBAL";
```

**获取当前用户信息**

```java
Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

if (principal instanceof UserDetails) {
String username = ((UserDetails)principal).getUsername();
} else {
String username = principal.toString();
}
```

**加载用户信息 实现The UserDetailsService**

```java
UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
```

**总结**

- `SecurityContextHolder`, to provide access to the `SecurityContext`.
- `SecurityContext`, to hold the `Authentication` and possibly request-specific security information.
- `Authentication`, to represent the principal in a Spring Security-specific manner.
- `GrantedAuthority`, to reflect the application-wide permissions granted to a principal.
- `UserDetails`, to provide the necessary information to build an Authentication object from your application’s DAOs or other source of security data.
- `UserDetailsService`, to create a `UserDetails` when passed in a `String`-based username (or certificate ID or the like).



#### 3.2 Authentication(认证)

**核心组件**

- [SecurityContextHolder](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-securitycontextholder) - The `SecurityContextHolder` is where Spring Security stores the details of who is [authenticated](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#authentication).
- [SecurityContext](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-securitycontext) - is obtained from the `SecurityContextHolder` and contains the `Authentication` of the currently authenticated user.
- [Authentication](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-authentication) - Can be the input to `AuthenticationManager` to provide the credentials a user has provided to authenticate or the current user from the `SecurityContext`.
- [GrantedAuthority](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-granted-authority) - An authority that is granted to the principal on the `Authentication` (i.e. roles, scopes, etc.)
- [AuthenticationManager](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-authenticationmanager) - the API that defines how Spring Security’s Filters perform [authentication](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#authentication).
- [ProviderManager](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-providermanager) - the most common implementation of `AuthenticationManager`.
- [AuthenticationProvider](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-authenticationprovider) - used by `ProviderManager` to perform a specific type of authentication.
- [Request Credentials with `AuthenticationEntryPoint`](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-authenticationentrypoint) - used for requesting credentials from a client (i.e. redirecting to a log in page, sending a `WWW-Authenticate` response, etc.)
- [AbstractAuthenticationProcessingFilter](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#servlet-authentication-abstractprocessingfilter) - a base `Filter` used for authentication. This also gives a good idea of the high level flow of authentication and how pieces work together.



##### 3.2.1 SecurityContextHolder

SecurityContextHolder 包含 SecurityContext



**Form Login 认证流程** 

![](https://upload-images.jianshu.io/upload_images/14019925-708373ec9e785515.png)







## 四，Servlet 安全



### 客户端请求流程图

<img src="https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/architecture/filterchain.png" style="zoom:67%;" />



客户端发送一个请求，中间要经过一条过滤链中的多个Filter，最终达到目标Servlet，Filter提供的作用

- 防止非法请求进入下游，Filter内部可以直接通过HttpServletResponse返回对应的结果
- 修改或者包装原有的HttpServletRequest和HttpServletResponse传入下游，已增强原有的功能(例:SecurityContextHolderAwareRequestFilter)



### DelegatingFilterProxy

DelegatingFilterProxy是Spring内部提供的一个类，本质上也是一个Filter继承自GenericFilterBean。此类的作用是桥接Servlet容器和Spring的ApplicationContext。

DelegatingFilterProxy可以通过标准的Servlet容器机制进行注册，但是把所有的工作都委派给实现了Filter的Spring Bean

**伪代码如下**

```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain {
    // 懒加载机制获取注册在Spring环境中的Filter，
    Filter delegate = getFilterBean(someBeanName);
    // 过滤工作委派给Spring Bean执行
    delegate.doFilter(request, response);
}
```

通过伪代码可以看出来，使用DelegatingFilterProxy还可以实现延迟查找Spring Filter Bean的作用。因为在Servlet容器启动前就需要完成Filter的注册，但是Spring Bean的初始化是晚于容器中Filter的注册时间的。通过延迟加载的方式可以很巧妙的解决这个问题





**请求流程图**

<img src="https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/architecture/delegatingfilterproxy.png" style="zoom:67%;" />





### FilterChainProxy

FilterChainProxy是Spring Secuirty提供的一个特殊的过滤器，内部通过SecurityFilterChain将请求委派给不同的Filter执行，一般情况下 FilterChainProxy 会充当DelegatingFilterProxy中的委派类，所有的工作将会交给他执行

**流程图**

![](https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/architecture/filterchainproxy.png)



### SecurityFilterChain

SecurityFilterChain用于FilterChainProxy 的内部，一个SecurityFilterChain内部会有多个Filter，相当于一条过滤器链，根据客户端的请求来确定应该走哪条过滤器链

**类结构**

```java
public interface SecurityFilterChain {

	boolean matches(HttpServletRequest request);

	List<Filter> getFilters();
}
```

SecurityFilterChain内部的Filter通常会被自动注册为Spring Bean，即使是手动new出来的对象，

FilterChainProxy为直接注册Servlet容器或DelegatingFilterProxy提供了许多优势



**1.它为Spring Security的Servlet提供了一个起点**

FilterChainProxy的内部的doFilter方法可以看作是Spring Security中Filter生效的起点，代码如下

```java
private void doFilterInternal(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		FirewalledRequest fwRequest = firewall
				.getFirewalledRequest((HttpServletRequest) request);
		HttpServletResponse fwResponse = firewall
				.getFirewalledResponse((HttpServletResponse) response);

    	// 找到当前请求所匹配的过滤器链
		List<Filter> filters = getFilters(fwRequest);

		if (filters == null || filters.size() == 0) {
			chain.doFilter(fwRequest, fwResponse);
			return;
		}

		VirtualFilterChain vfc = new VirtualFilterChain(fwRequest, chain, filters);
		vfc.doFilter(fwRequest, fwResponse);
}

private List<Filter> getFilters(HttpServletRequest request) {
		for (SecurityFilterChain chain : filterChains) {
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}

		return null;
}

```

通过代码可以看出来，FilterChainProxy内部会根据当前请求去找到和他匹配的SecurityFilterChain，然后获取对应的Filter进行执行。通过断点的方式可以很清晰的看出来当前请求会经过哪些Filter，使用这种方式有几种好处

1. 可以灵活的决定哪一个SecurityFilterChain应该被执行，在传统的Servlet容器中，一般是通过配置URL的方式来进行Filter过滤，但是通过实现RequestMatcher就可以基于HttpServletRequest中任意的数据来进行判定哪些Filter可以被调用
2. 可以为程序不同的部分进行独立配置



**2.FilterChainProxy是Spring Security的中心**

站在全局的角度上看FilterChainProxy，他可以为我们执行一些收尾工作，比如清理资源，代码如下：

```java
public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
		if (clearContext) {
			try {
				request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
				doFilterInternal(request, response, chain);
			}
			finally {
                // 清理SecurityContext上下文，防止内存溢出
				SecurityContextHolder.clearContext();
				request.removeAttribute(FILTER_APPLIED);
			}
		}
		else {
			doFilterInternal(request, response, chain);
		}
}
```

由于SecurityContextHolder内部默认使用ThreaLocal来存储当前的用户认证信息，如果不及时清理会造成内存溢出，FilterChainProxy可以消除这个隐患，并且其内部还使用了HttpFirewall来保护程序免受一些常见的攻击。



**流程图**

<img src="https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/architecture/multi-securityfilterchain.png" style="zoom: 80%;" />

在上图中可以看到在当前程序中存在两条SecurityFilterChain，只有第一个匹配的SecurityFilterChain会被调用，j假设路径为`/api/**`，第一个SecurityFilterChain将会执行，如果请求路径为`/messages/`，第一次个SecurityFilterChain将不会匹配，所以继续往下匹配，如果一直没有匹配到最终会匹配到最后一个SecurityFilterChain，每个SecurityFilterChain中可以自定义不同的过滤器，配置完全独立。



### SecurityFilters

**Filter顺序及作用**

- **ChannelProcessingFilter**：一般用来做https和http切换使用

- **WebAsyncManagerIntegrationFilter**：用于集成SecurityContext到Spring异步执行机制中的WebAsyncManager。用来处理异步请求的安全上下文

- **SecurityContextPersistenceFilter：** 在请求来临时把Authentication读取到SecurityContextHolder中，在请求结束时清除SecurityContextHolder，并把最新的Authentication存储起来以供下次使用

- **HeaderWriteFilter:** 给响应添加一些Header，比如 `X-Frame-Options`, `X-XSS-Protection` ，`X-Content-Type-Options`等

- **CorsFilter：** 跨域相关

- **CsrfFilter：** 防御csrf攻击

- **LogoutFilter：** 登出过滤器

- **OAuth2AuthorizationRequestRedirectFilter：** Oauth请求重定向相关逻辑，需要引入spring-scurity-oauth2相关模块

- **Saml2WebSsoAuthenticationRequestFilter：** 基于 `SMAL` 的 `SSO` 单点登录请求认证过滤器。

- **X509AuthenticationFilter：** X509相关配置

- **AbstractPreAuthenticatedProcessingFilter：** 主要作用是从传入请求中提取主体上的必要信息，而不是对它们进行身份验证。

- **CasAuthenticationFilter：** Cas登录相关

- **OAuth2LoginAuthenticationFilter：** Oauth2登陆相关

- **Saml2WebSsoAuthenticationFilter：** 基于 `SMAL` 的 `SSO` 单点登录认证过滤器

- **UsernamePasswordAuthenticationFilter：** 基于用户名密码登录的校验处理逻辑

- **OpenIDAuthenticationFilter：** 基于OpenID认证过滤

- **DefaultLoginPageGeneratingFilter：** 生成登陆页面，登陆成功和登录错误页面

- **DefaultLogoutPageGeneratingFilter：** 生成登出页面

- **ConcurrentSessionFilter：** 做session并发控制，比如控制一个账号只能有一个在线

- **DigestAuthenticationFilter：** `DigestAuthenticationFilter` 能够处理 `HTTP` 头中显示的摘要式身份验证凭据。你可以通过 `HttpSecurity#addFilter()` 来启用和配置相关功能。

- **BasicAuthenticationFilter :** `asicAuthenticationFilter` 负责处理 `HTTP` 头中显示的基本身份验证凭据。这个 **Spring Security** 的 **Spring Boot** 自动配置默认是启用的 。

  `BasicAuthenticationFilter` 通过 `HttpSecurity#httpBasic()` 及相关方法引入其配置对象 `HttpBasicConfigurer` 来进行配置。

- **RequestCacheAwareFilter：** 用于用户认证成功后，重新恢复因为登录被打断的请求。当匿名访问一个需要授权的资源时。会跳转到认证处理逻辑，此时请求被缓存。在认证逻辑处理完毕后，从缓存中获取最开始的资源请求进行再次请求。

- **SecurityContextHolderAwareRequestFilter：** 对原有的HttpServletRequest进行包装，增强。包装后的request对象对Servlet中的安全方法进行了实现

  `HttpServletRequest.authenticate(HttpServletResponse) `

  `HttpServletRequest.login(String, String) `

  `HttpServletRequest.logout()`

  `AsyncContext.start(Runnable) `
  
- **JaasApiIntegrationFilter：** 对Java认证和授权提供支持

- **RememberMeAuthenticationFilter：** 对rememberMe功能提供支持

- **AnonymousAuthenticationFilter: ** 匿名认证过滤器，所有未登录的用户都会被授予匿名身份

- **OAuth2AuthorizationCodeGrantFilter: ** 

- **SessionManagementFilter：** 提供Session管理，如Session固定攻击，Session并发控制等

- **ExceptionTranslationFilter：** 主要是用来处理FilterSecurityInterceptor抛出的异常，如果抛出AccessDeniedException，并且当前Authentication对象是AnonymousAuthentication或RememberMeAuthenticationToken，则将异常转换为InsufficientAuthenticationException，并交由成员变量AuthenticationEntryPoint 进行处理，否则会交由AccessDeniedHandler进行处理，如果程序不抛出AccessDeniedException或AuthenticationException，ExceptionTranslationFilter将不做任何处理

- **FilterSecurityInterceptor：** 权限控制的核心

- **SwitchUserFilter：** 提供切换用户的支持



### Handling Security Exceptions

异常处理流程

<img src="https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/architecture/exceptiontranslationfilter.png" style="zoom:67%;" />

1. ExcetionTranslationFilter调用FilterChain.doFilter执行剩下的请求
2. 如果用户未认证或者后面的Filter抛出AuthenticationException
   - 清除SecurityContextHolder
   - 将HttpServletRequest保存在RequestCache，如果用户成功认证可以通过RequestCache重放原始请求
   - 将后续操作委派给AuthenticationEntryPoint处理。内部可以重定向登录页面或者返回自定义信息
3. 说明是AccessDeniedException，交给AccessDeniedHandler进行处理

**伪代码**

```java
try {
    filterChain.doFilter(request, response); 
} catch (AccessDeniedException | AuthenticationException ex) {
    if (!authenticated || ex instanceof AuthenticationException) {
        startAuthentication(); 
    } else {
        accessDenied(); 
    }
}
```



## 五，认证组件和机制



### 5.1 SecurityContextHolder

SecurityContextHolder是Spring Security认证模型中的核心组件，其内部包含了SecurityContext。默认采用ThreadLocal存储，也支持自定义存储策略。主要作用是存放已经验证通过用户的信息

表明一个用户验证通过最简单的办法就是直接将Authentication存放到SecurityContextHolder中，例：

```java
SecurityContext context = SecurityContextHolder.createEmptyContext(); 
Authentication authentication =
    new TestingAuthenticationToken("username", "password", "ROLE_USER"); 
context.setAuthentication(authentication);

SecurityContextHolder.setContext(context); 
```

SecurityContextHolder.createEmptyContext() 使用该方法创建SecurityContext而不使用SecurityContextHolder.getContext().setAuthentication(authentication) 这种方式的好处在于可以避免多线程之间发生竞争

**存储策略**

SecurityContextHolder 内部默认提供了三种存储SecurityContext的策略，分别是 ThreadLocal，InheritableThreadLocal，MODE_GLOBAL(内部使用静态字段存储，即所有线程都可以访问到)，

有两种方法可以指定存储策略

- 设置系统属性spring.security.strategy
- SecurityContextHolder#setStrategyName

结构图

![](https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/authentication/architecture/securitycontextholder.png)



### 5.2 SecurityContext

 存储在SecurityContextHolder中的对象，内部包含当前用户的Authentication对象

### 5.3 Authentication

Authentication对象有两个主要作用

- 作为AuthenticationManager的输入，用于提供身份验证
- 代表当前已认证通过的用户，可以从SecuriyContext中获取

Authentication包含下面几种对象

- `principal` 用户标识符，当使用UsernamePasswordToken时，principal通常是UserDetail对象
- `credential` 通常代表password，认证通过后，会被清除 以防泄露
- `authorities` `GrantedAuthority`代表当前用户被赋予的权限，比如rule或者scopes

### 5.4 GrantedAuthority

GrantedAuthority 代表前用户所被授予的权限，如role或scopes，通常被UserDetailService加载

### 5.5  AuthenticationManager

AuthenticationManager 主要用户执行用户认证相关逻辑，集成在Security Filter中，如果不使用Security Filter可以直接使用SecurityContextHolder，常用实现类：ProviderManager

### 5.6 ProviderManager

ProviderManager是最常用的AuthenticationManager实现类，ProviderManager将具体认证逻辑委派给AuthenticationProvider 列表。遍历AuthenticationProvider列表，找出能支持当前Authentication对象的AuthenticationProvider然后交由他执行认证，如果不支持则继续遍历。如果未能找到对应的AuthenticationProvider则触发ProviderNotFountException

结构图

<img src="https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/authentication/architecture/providermanager.png" style="zoom: 80%;" />



### 5.7 AuthenticationProvider

每个AuthenticationProvider都为指定类型的Authentication提供验证，例如`DaoAuthenticationProvider`supports username/password based authentication while `JwtAuthenticationProvider` supports authenticating a JWT token.

### 5.8 AuthenticationEntryPoint

一般用于处理用户未登录状态，使用AuthenticationEntryPoint，可以重定向到登录页，如果在前后端分离的架构中可以返回自定义信息

### 5.9 AbstractAuthenticationProcessingFilter

 用于认证的基础Filter，内部抽象出了公共的代码。认证流程图：

<img src="https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/authentication/architecture/abstractauthenticationprocessingfilter.png" style="zoom:80%;" />

1. 根据用户输入的认证信息(例：用户名和密码)构建`Authentication`，`Authentication`的具体类型由`AbstractAuthenticationProcessingFilte`r的子类构建，比如`UsernamePasswordFilter`会创建`UsernamePasswordAuthenticationToken`

2. 然后将`Authentication`对象交由`AuthenticationManager`执行认证

3. 如果认证失败

   - `SecurityContextHolder`会被清空
   - `RememberMeServices#loginFail 执行`
   - `AuthenticationFailureHandler`执行

   源码：AbstractAuthenticationProcessingFilter#unsuccessfulAuthentication
   
4. 如果认证成功

   - `SessionAuthenticationStrategy#onAuthentication` 执行
   - `Authentication`存入`SecurityContextHolder`中，等请求完成之后`SecurityContextPersistenceFilter`会将`SecurityContext`存入`HttpSession`中。
   - `RememberMeServices#loginSuccess`会执行
   - `ApplicationEventPublisher` 发布事件：`InteractiveAuthenticationSuccessEvent`
   - `AuthenticationSuccessHandler` 执行

   源码：AbstractAuthenticationProcessingFilter#successfulAuthentication



### 5.10 Username/Password Authentication

#### 5.10.1 PasswordEncoder

通过暴露PasswordEncoder的Bean即可将自定义的PasswordEncoder集成到Spring Security中

#### 5.10.2 DaoAuthenticationProvider

DaoAuthenticationProvider为AuthenticationProvider的实现类，内部使用`UserDetailService`和`PasswordEncoder` 验证用户名和密码。流程图如下：

<img src="https://docs.spring.io/spring-security/site/docs/5.4.6/reference/html5/images/servlet/authentication/unpwd/daoauthenticationprovider.png" style="zoom:80%;" />



### 5.11 SessionManagement

Http session 相关的功能是通过`SessionManagementFilter`和`SessionAuthenticationStrategy`组合来处理的，包含基本功能为：会话固定保护，攻击预防，会话超时检测，同一用户的session并发处理

#### 5.11.1 超时检测

通过配置超时处理策略`InvalidSessionStrategy`可以控制浏览器提交无效Session上来之后程序的应当做出怎样的处理行为，

Java 配置

```java
 protected void configure(HttpSecurity http) throws Exception {
        http
            // ...
            .sessionManagement()
            .invalidSessionStrategy(new CustomerInvalidSessionStrategy())
            // ...
    }
```



#### 5.11.2 Session 并发控制

通过配置sessionConcurrency可以控制限制用户的会话数，比如QQ登录，第二次登录会导致第一次会话失效

详细配置即说明见`SessionManagementConfigurer`的内部类`ConcurrencyControlConfigurer`



#### 5.11.3 Session 固定攻击保护

会话固定攻击是攻击者通过访问某个网站而产生一个session，随后去诱骗用户使用相同会话去登录(例：通过向用户发送一个包含会话标识符作为参数的链接)。当用户登录成功之后，攻击者这边也会自动登录。

Spring Security默认提供三种方式抵御此攻击

- **newSession：** 登录成功创建一个新session
- **migrateSession：** 登录成功创建新session，然后复制老session中的数据到新session
- **changeSessionId：** 只更改sessionId（HttpServletRequest#changeSessionId()）



#### 5.11.4 SessionManagementFilter

在当前线程中的`SecurityContextRepository`是否有用户上下文信息，如果没有，并且判断`SecurityContextHolder的Authentication`不为空并且不是匿名访问，则执行`SessionAuthenticationStrategy.onAuthentication` 方法。否则判断当前sessionId是否有效，如果无效则执行，`InvalidSessionStrategy.onInvalidSessionDetected`

#### 5.11.5 SessionAuthenticationStrategy

`SessionAuthenticationStrategy`在`SessionManagementFilter`和`AbstractAuthenticationProcessingFilter`，都有用到，所以两个地方都需要配置，

注:

> 在`HttpSessionBindingListener`和`SessionFixationProtectionStrategy`同时使用时可能造成问题，因为`SessionFixationProtectionStrategy`中会对session中的属性重新设置



#### 5.11.6 Concurrency Control(Session并发控制)

Spring Security可以控制一个用户在一个程序中能够同时拥有多少会话。并且可以控制当检测到用户超过指定会话数量时程序应当作出怎么的反应。Spring Security针对会话超出，内部提供了两种应对措施。

1. **最后一个会话建立时，会使最早创建的会话过期**

   业界普遍采用这种方式，比如QQ，微信

2. **当检测到会话数量已达到最大时，阻止新会话的创建**

   使用此种方式时，如果之前一个会话已经创建，在使用完成后并没有执行登出操作(比如直接关闭了浏览器)，那么当前会话在有效期内一直存在，会导致此账号在这一段时间之内无法登录。

控制会话的逻辑由`SessionAuthenticationStrategy` 的子类`ConcurrentSessionControlAuthenticationStrategy` 实现



**ConcurrentSessionFilter**

在`ConcurrentSessionFilter`中会判断`SessionRegistry`中的当前会话是否过期，如果过期，则调用`SessionInformationExpiredStrategy.onExpiredSessionDetected`进行处理，默认实现为`ResponseBodySessionInformationExpiredStrategy`

**SessionRegistry**

在SessionRegistry中，会存储当前程序所有的会话。可以使用该类中的方法进行一个特殊操作，比如作为管理员可以强制登出某个用户的账号等等。想要实现这种自定义从操作可以将`SessionRegistry`注册为Spring的一个Bean。后续注入到程序中使用，例

```java
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        	http.sessionManagement()
                .sessionConcurrency(configure -> {
                    configure.maximumSessions(-1);
                    configure.sessionRegistry(sessionRegistry());
                });
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
}

```

将`maximumSessions` 属性设置成-1表示，不限制用户会话数



### 5.12 Remember-Me Authentication

通常网站登录界面都会有记住我功能，此功能本质上是利用cookie实现，Spring Security 提供了两种实现

注：两种方式都需要配置UserDetailService

#### 5.12.1 Simple Hash-Based Token Approach (基于Hash算法)

使用此种方式生成的token包含三段rm

```tex
base64(username + ":" + expirationTime + ":" +
md5Hex(username + ":" + expirationTime + ":" password + ":" + key))

username:          As identifiable to the UserDetailsService
password:          That matches the one in the retrieved UserDetails
expirationTime:    The date and time when the remember-me token expires, expressed in milliseconds
key:               A private key to prevent modification of the remember-me token
```

首先根据username找到用户，然后将用户名过期时间密码和签名key进行MD5计算，如果cookie中的remember token和计算后的结果一样，在交由ProviderManager进行key的验证，通过即登录成功



#### 5.12.2  Persistent Token Approach

持久化Token方式，将remember-token存在数据库中



### 5.13 Run As Authentication Replacement



### 5.14 Handling Logout

通过在`LogoutFilter`中配置`LogoutHandler`可以实现自定义的登出功能。

在`LogoutHanler`执行完之后`LogoutSuccessHandler` 会被执行。

`LogoutFilter`和`LogoutSuccessHandler`的区别是前者不应该抛出异常，后者可以



# 六，授权组件和机制

### 6.1 Authorization Architecture

#### 6.1.1 Authorities

Authorities表示用户所被授权的权限集合，存放在当前用户的`Authentication` 对象中。



#### 6.1.2 Pre-Invocation Handling

在请求真正被执行之前要经历一次预处理，一般在此操作中判断是否有相应的权限调用接口或者方法。内部使用`AccessDecisionManager`实现

**AccessDecisionManager**

`AccessDecisionManager`被`AbstractSecurityInterceptor`调用来做最终的访问控制， 底层基于投票机制来实现访问控制，内部有多个投票者`AccessDecisionVoter`进行投票，根据不同的模式来决定是否允许通过

![](https://docs.spring.io/spring-security/site/docs/current/reference/html5/images/access-decision-voting.png)

1. **AffirmativeBased**

   `AffirmativeBased`基于乐观投票模式，如果任意一个投票者投出赞成票，则允许此次请求通过访问。如果所有投票者都弃权会通过属性`allowIfAllAbstainDecisions` 来决定请求允许通过

2. **ConsensusBased**

   `ConsensusBased`基于公平投票模式，如果赞成票比反对票多则通过，反之不通过。如果两者票数一致则通过属性`allowIfEqualGrantedDeniedDecisions`决定是否通过，如果所有投票者弃权，则通过``allowIfAllAbstainDecisions` `决定程序最终行为

3. **UnanimousBased**

   `UnanimousBased`基于悲观投票模式。如果任意一个投票者投出反对票，则拒绝此次请求。如果所有投票者弃权则通过属性`allowIfAllAbstainDecisions` 决定程序最终行为






















































































