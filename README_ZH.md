# web_webview

#### 介绍
webview是Openharmony web组件的Native引擎,基于Chromium和CEF构建。

#### 软件架构
软件架构说明

        -----------------------
        |      web组件        |
        -----------------------
        |      webview        |
        -----------------------
        |        CEF          |
        -----------------------
        |      Chromium       |
        -----------------------
        |  Openharmony基础库  |
        -----------------------
 
 web组件：Openharmony的UI组件
 webview: 基于CEF构建的Openharmony web Native引擎
 CEF：CEF全称Chromium Embedded Framework，是一个基于Google Chromium 的开源项目
 Chromium: Chromium是一个由Google主导开发的网页浏览器。以BSD许可证等多重自由版权发行并开放源代码

 #### 目录结构
.
├── interfaces                   # 提供给组件调用的接口层
│   └── innerkits
│       └── ohos_nweb
├── ohos_nweb                    # 适配Openharmony的框架层
│   ├── include
│   └── src
└── test                         # 单元测试代码
    └── ohos_nweb



#### 相关仓
ace_ace_engine

third_party_cef

web_webview

third_party_chromium

