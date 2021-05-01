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



























































































