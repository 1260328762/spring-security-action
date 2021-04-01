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





















































































































