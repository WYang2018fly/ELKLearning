# ELK(elastic stack)Learning

## 一、ELK的组成
- elasticsearch: 搜索和分析引擎
- logstash: 服务器端数据处理管道，能够同时从多个来源采集数据，转换数据，然后将数据发送到诸如 Elasticsearch 等“存储库”中
- kibana: 让用户在 Elasticsearch 中使用图形和图表对数据进行可视化
- beats: 一系列轻量型的单一功能数据采集器
  - filebeat: 用于监控、收集日志文件



## 二、elasticsearch(ES)

### 1.安装

> By docker image

```powershell
PS C:\Users\24216> docker pull elasticsearch:7.9.3
7.9.3: Pulling from library/elasticsearch
75f829a71a1c: Pull complete
2dd8aabff665: Pull complete
fd17121b3976: Pull complete
a19cf707b4fd: Pull complete
4ccdd8a52dc0: Pull complete
d018d3fc07a4: Pull complete
70f1e3a1960a: Pull complete
8f58f7e426fa: Pull complete
817feb91b55c: Pull complete
Digest: sha256:a13cd87cbf139fadbca64972ef2c8777222236887d303e4177c1ab7cff1b52f6
Status: Downloaded newer image for elasticsearch:7.9.3

PS C:\Users\24216> docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
elasticsearch       7.9.3               1ab13f928dc8        2 weeks ago         742MB
```

### 2.启动

```powershell
PS C:\Users\24216> docker run --name elasticsearch -p 9200:9200 -p 9300:9300 -e "privileged=true" -e "discovery.type=single-node" -d elasticsearch:7.9.3
# --name  elasticsearch 容器名称
# -p 9200:9200 -p 9300:9300 映射端口
# -e "privileged=true" 配置访问权限
# -e "discovery.type=single-node" 指定elasticsearch部署模式
# -d 后台运行
# elasticsearch:7.9.3指定镜像

PS C:\Users\24216> docker ps
CONTAINER ID        IMAGE                 COMMAND                  CREATED             STATUS              PORTS                                            NAMES
4b36c950b789        elasticsearch:7.9.3   "/tini -- /usr/local°≠"   2 minutes ago       Up 2 minutes        0.0.0.0:9200->9200/tcp, 0.0.0.0:9300->9300/tcp   elasticsearch
```

### 3.访问

通过browser访问http://192.168.99.100:9200/

```json
{
	"name": "4b36c950b789",
  "cluster_name": "docker-cluster",
  "cluster_uuid": "F6b654SZRpSjUVJgIAiXZA",
  "version": {
  "number": "7.9.3",
  "build_flavor": "default",
  "build_type": "docker",
  "build_hash": "c4138e51121ef06a6404866cddc601906fe5c868",
  "build_date": "2020-10-16T10:36:16.141335Z",
  "build_snapshot": false,
  "lucene_version": "8.6.2",
  "minimum_wire_compatibility_version": "6.8.0",
  "minimum_index_compatibility_version": "6.0.0-beta1"
  },
  "tagline": "You Know, for Search"
}
```



## 三、kibana

### 1.安装

> By docker image

```powershell
PS C:\Users\24216> docker pull kibana:7.9.3
7.9.3: Pulling from library/kibana
75f829a71a1c: Already exists
27675ba9d981: Pull complete
dce5d1796f35: Pull complete
b9f272a0e2df: Pull complete
838399eee2be: Pull complete
3e5a440a6c4a: Pull complete
38f6fac0ff65: Pull complete
6bc7164808f0: Pull complete
db227852f150: Pull complete
55e74ce8834c: Pull complete
46d008667a80: Pull complete
Digest: sha256:81638b717f8901debd331df46da38e7775f2685d81c1ed5e92e25bc17d370f4d
Status: Downloaded newer image for kibana:7.9.3

PS C:\Users\24216> docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
kibana              7.9.3               f9f7fac59a10        2 weeks ago         1.18GB
elasticsearch       7.9.3               1ab13f928dc8        2 weeks ago         742MB
```

### 2.启动

```powershell
docker run -d --name kibana -e ELASTICSEARCH_URL=http://192.168.99.100:9200 -p 5601:5601 kibana:7.9.3
```

### 3.访问

通过浏览器访问http://192.168.99.100:5601,可以看到kibana的可视化界面的HOME页

```
Observability
APM
APM automatically collects in-depth performance metrics and errors from inside your applications.

Add APM
Logs
Ingest logs from popular data sources and easily visualize in preconfigured dashboards.

Add log data
Metrics
Collect metrics from the operating system and services running on your servers.

Add metric data
Security
SIEM + Endpoint Security
Protect hosts, analyze security information and events, hunt threats, automate detections, and create cases.

Add events
Add sample data
Load a data set and a Kibana dashboard
Upload data from log file
Import a CSV, NDJSON, or log file
Use Elasticsearch data
Connect to your Elasticsearch index
Visualize and Explore Data
APM
Automatically collect in-depth performance metrics and errors from inside your applications.


App Search
Leverage dashboards, analytics, and APIs for advanced application search made simple.

Canvas
Showcase your data in a pixel-perfect way.

Dashboard
Display and share a collection of visualizations and saved searches.

Discover
Interactively explore your data by querying and filtering raw documents.

Graph
Surface and analyze relevant relationships in your Elasticsearch data.

Logs
Stream logs in real time or scroll through historical views in a console-like experience.

Machine Learning
Automatically model the normal behavior of your time series data to detect anomalies.

Maps
Explore geospatial data from Elasticsearch and the Elastic Maps Service

Metrics
Explore infrastructure metrics and logs for common servers, containers, and services.

Security
Explore security metrics and logs for events and alerts

Uptime
Uptime monitoring

Visualize
Create visualizations and aggregate data stores in your Elasticsearch indices.


Workplace Search
Search all documents, files, and sources available across your virtual workplace.

Manage and Administer the Elastic Stack
Console
Skip cURL and use this JSON interface to work with your data directly.

Rollups
Summarize and store historical data in a smaller index for future analysis.

Saved Objects
Import, export, and manage your saved searches, visualizations, and dashboards.

Security Settings
Protect your data and easily manage who has access to what with users and roles.

Spaces
Organize your dashboards and other saved objects into meaningful categories.

Stack Monitoring
Track the real-time health and performance of your Elastic Stack.

Transforms
Use transforms to pivot existing Elasticsearch indices into summarized or entity-centric indices.

Didn’t find what you were looking for?

View full directory of Kibana plugins
```

## 四、beats

### 1.filebeat

- 安装

  >On windows

  官网download filebeat-7.9.3-windows-x86_64压缩包,解压复制到D:\Application

  ```powershell
  PS D:\Application\filebeat-7.9.3-windows-x86_64> ls
  Mode                LastWriteTime         Length Name
  ----                -------------         ------ ----
  d-----        2020/11/1     17:23                data
  d-----        2020/11/1     16:56                kibana
  d-----        2020/11/1     16:56                module
  d-----        2020/11/1     16:56                modules.d
  -a----       2020/10/16      9:20             41 .build_hash.txt
  -a----       2020/10/16      9:16        2402200 fields.yml
  -a----       2020/10/16      9:18       75837952 filebeat.exe
  -a----       2020/10/16      9:16         114090 filebeat.reference.yml
  -a----        2020/11/1     17:23           8949 filebeat.yml
  -a----       2020/10/16      9:20            879 install-service-filebeat.ps1
  -a----       2020/10/16      8:12          13675 LICENSE.txt
  -a----       2020/10/16      8:13        8440372 NOTICE.txt
  -a----       2020/10/16      9:20            809 README.md
  -a----       2020/10/16      9:20            250 uninstall-service-filebeat.ps1
  ```

  

- 配置

  （1）采集日志的目录路径

  （2）enable: true

  （3）output: elasticsearch或logstash (only配置一个输出,default elasticsearch)

  ```yml
  ###################### Filebeat Configuration Example #########################
  
  # This file is an example configuration file highlighting only the most common
  # options. The filebeat.reference.yml file from the same directory contains all the
  # supported options with more comments. You can use it as a reference.
  #
  # You can find the full configuration reference here:
  # https://www.elastic.co/guide/en/beats/filebeat/index.html
  
  # For more available modules and options, please see the filebeat.reference.yml sample
  # configuration file.
  
  # ============================== Filebeat inputs ===============================
  
  filebeat.inputs:
  
  # Each - is an input. Most options can be set at the input level, so
  # you can use different inputs for various configurations.
  # Below are the input specific configurations.
  
  - type: log
  
    # Change to true to enable this input configuration.
    enabled: true
  
    # Paths that should be crawled and fetched. Glob based paths.
    paths:
  		#需要采集的日志目录
      - D:\var\log\cron-booking\*
      #- /var/log/*.log
      #- c:\programdata\elasticsearch\logs\*
  
    # Exclude lines. A list of regular expressions to match. It drops the lines that are
    # matching any regular expression from the list.
    #exclude_lines: ['^DBG']
  
    # Include lines. A list of regular expressions to match. It exports the lines that are
    # matching any regular expression from the list.
    #include_lines: ['^ERR', '^WARN']
  
    # Exclude files. A list of regular expressions to match. Filebeat drops the files that
    # are matching any regular expression from the list. By default, no files are dropped.
    #exclude_files: ['.gz$']
  
    # Optional additional fields. These fields can be freely picked
    # to add additional information to the crawled log files for filtering
    #fields:
    #  level: debug
    #  review: 1
  
    ### Multiline options
  
    # Multiline can be used for log messages spanning multiple lines. This is common
    # for Java Stack Traces or C-Line Continuation
  
    # The regexp Pattern that has to be matched. The example pattern matches all lines starting with [
    #multiline.pattern: ^\[
  
    # Defines if the pattern set under pattern should be negated or not. Default is false.
    #multiline.negate: false
  
    # Match can be set to "after" or "before". It is used to define if lines should be append to a pattern
    # that was (not) matched before or after or as long as a pattern is not matched based on negate.
    # Note: After is the equivalent to previous and before is the equivalent to to next in Logstash
    #multiline.match: after
  
  # ============================== Filebeat modules ==============================
  
  filebeat.config.modules:
    # Glob pattern for configuration loading
    path: ${path.config}/modules.d/*.yml
  
    # Set to true to enable config reloading
    reload.enabled: false
  
    # Period on which files under path should be checked for changes
    #reload.period: 10s
  
  # ======================= Elasticsearch template setting =======================
  
  setup.template.settings:
    index.number_of_shards: 1
    #index.codec: best_compression
    #_source.enabled: false
  
  
  # ================================== General ===================================
  
  # The name of the shipper that publishes the network data. It can be used to group
  # all the transactions sent by a single shipper in the web interface.
  #name:
  
  # The tags of the shipper are included in their own field with each
  # transaction published.
  #tags: ["service-X", "web-tier"]
  
  # Optional fields that you can specify to add additional information to the
  # output.
  #fields:
  #  env: staging
  
  # ================================= Dashboards =================================
  # These settings control loading the sample dashboards to the Kibana index. Loading
  # the dashboards is disabled by default and can be enabled either by setting the
  # options here or by using the `setup` command.
  #setup.dashboards.enabled: false
  
  # The URL from where to download the dashboards archive. By default this URL
  # has a value which is computed based on the Beat name and version. For released
  # versions, this URL points to the dashboard archive on the artifacts.elastic.co
  # website.
  #setup.dashboards.url:
  
  # =================================== Kibana ===================================
  
  # Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
  # This requires a Kibana endpoint configuration.
  setup.kibana:
  
    # Kibana Host
    # Scheme and port can be left out and will be set to the default (http and 5601)
    # In case you specify and additional path, the scheme is required: http://localhost:5601/path
    # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
    #host: "localhost:5601"
  
    # Kibana Space ID
    # ID of the Kibana Space into which the dashboards should be loaded. By default,
    # the Default Space will be used.
    #space.id:
  
  # =============================== Elastic Cloud ================================
  
  # These settings simplify using Filebeat with the Elastic Cloud (https://cloud.elastic.co/).
  
  # The cloud.id setting overwrites the `output.elasticsearch.hosts` and
  # `setup.kibana.host` options.
  # You can find the `cloud.id` in the Elastic Cloud web UI.
  #cloud.id:
  
  # The cloud.auth setting overwrites the `output.elasticsearch.username` and
  # `output.elasticsearch.password` settings. The format is `<user>:<pass>`.
  #cloud.auth:
  
  # ================================== Outputs ===================================
  
  # Configure what output to use when sending the data collected by the beat.
  
  # ---------------------------- Elasticsearch Output ----------------------------
  output.elasticsearch:
    # Array of hosts to connect to.
    #设置elasticsearch的IP和port
    hosts: ["192.168.99.100:9200"]
  
    # Protocol - either `http` (default) or `https`.
    #protocol: "https"
  
    # Authentication credentials - either API key or username/password.
    #api_key: "id:api_key"
    #username: "elastic"
    #password: "changeme"
  
  # ------------------------------ Logstash Output -------------------------------
  #output.logstash:
    # The Logstash hosts
    #hosts: ["localhost:5044"]
  
    # Optional SSL. By default is off.
    # List of root certificates for HTTPS server verifications
    #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]
  
    # Certificate for SSL client authentication
    #ssl.certificate: "/etc/pki/client/cert.pem"
  
    # Client Certificate Key
    #ssl.key: "/etc/pki/client/cert.key"
  
  # ================================= Processors =================================
  processors:
    - add_host_metadata:
        when.not.contains.tags: forwarded
    - add_cloud_metadata: ~
    - add_docker_metadata: ~
    - add_kubernetes_metadata: ~
  
  # ================================== Logging ===================================
  
  # Sets log level. The default log level is info.
  # Available log levels are: error, warning, info, debug
  #logging.level: debug
  
  # At debug level, you can selectively enable logging only for some components.
  # To enable all selectors use ["*"]. Examples of other selectors are "beat",
  # "publish", "service".
  #logging.selectors: ["*"]
  
  # ============================= X-Pack Monitoring ==============================
  # Filebeat can export internal metrics to a central Elasticsearch monitoring
  # cluster.  This requires xpack monitoring to be enabled in Elasticsearch.  The
  # reporting is disabled by default.
  
  # Set to true to enable the monitoring reporter.
  #monitoring.enabled: false
  
  # Sets the UUID of the Elasticsearch cluster under which monitoring data for this
  # Filebeat instance will appear in the Stack Monitoring UI. If output.elasticsearch
  # is enabled, the UUID is derived from the Elasticsearch cluster referenced by output.elasticsearch.
  #monitoring.cluster_uuid:
  
  # Uncomment to send the metrics to Elasticsearch. Most settings from the
  # Elasticsearch output are accepted here as well.
  # Note that the settings should point to your Elasticsearch *monitoring* cluster.
  # Any setting that is not set is automatically inherited from the Elasticsearch
  # output configuration, so if you have the Elasticsearch output configured such
  # that it is pointing to your Elasticsearch monitoring cluster, you can simply
  # uncomment the following line.
  #monitoring.elasticsearch:
  
  # ============================== Instrumentation ===============================
  
  # Instrumentation support for the filebeat.
  #instrumentation:
      # Set to true to enable instrumentation of filebeat.
      #enabled: false
  
      # Environment in which filebeat is running on (eg: staging, production, etc.)
      #environment: ""
  
      # APM Server hosts to report instrumentation results to.
      #hosts:
      #  - http://localhost:8200
  
      # API Key for the APM Server(s).
      # If api_key is set then secret_token will be ignored.
      #api_key:
  
      # Secret token for the APM Server(s).
      #secret_token:
  
  
  # ================================= Migration ==================================
  
  # This allows to enable 6.7 migration aliases
  #migration.6_to_7.enabled: true
  ```

- 启动

  ```powershell
  PS D:\Application\filebeat-7.9.3-windows-x86_64> .\filebeat.exe -e -c filebeat.yml
  2020-11-01T17:23:22.999+0800    INFO    instance/beat.go:640    Home path: [D:\Application\filebeat-7.9.3-windows-x86_64] Config path: [D:\Application\filebeat-7.9.3-windows-x86_64] Data path: [D:\Application\filebeat-7.9.3-windows-x86_64\data] Logs path: [D:\Application\filebeat-7.9.3-windows-x86_64\logs]
  2020-11-01T17:23:23.000+0800    INFO    instance/beat.go:648    Beat ID: 45fad53b-5d69-43da-a7d7-17be91733a3d
  2020-11-01T17:23:23.195+0800    INFO    [beat]  instance/beat.go:976    Beat info       {"system_info": {"beat": {"path": {"config": "D:\\Application\\filebeat-7.9.3-windows-x86_64", "data": "D:\\Application\\filebeat-7.9.3-windows-x86_64\\data", "home": "D:\\Application\\filebeat-7.9.3-windows-x86_64", "logs": "D:\\Application\\filebeat-7.9.3-windows-x86_64\\logs"}, "type": "filebeat", "uuid": "45fad53b-5d69-43da-a7d7-17be91733a3d"}}}
  2020-11-01T17:23:23.197+0800    INFO    [beat]  instance/beat.go:985    Build info      {"system_info": {"build": {"commit": "7aab6a9659749802201db8020c4f04b74cec2169", "libbeat": "7.9.3", "time": "2020-10-16T09:16:15.000Z", "version": "7.9.3"}}}
  2020-11-01T17:23:23.197+0800    INFO    [beat]  instance/beat.go:988    Go runtime info {"system_info": {"go": {"os":"windows","arch":"amd64","max_procs":4,"version":"go1.14.7"}}}
  2020-11-01T17:23:23.297+0800    INFO    [beat]  instance/beat.go:992    Host info       {"system_info": {"host": {"architecture":"x86_64","boot_time":"2020-10-31T08:23:02.15+08:00","name":"DESKTOP-OVSLAMI","ip":["fe80::a45e:d1d:28fd:c62f/64","169.254.198.47/16","fe80::bdb7:f9c6:1165:aa93/64","192.168.137.1/24","fe80::5dd4:bd0d:9e3f:38f2/64","192.168.153.1/24","fe80::ec51:fdbd:a17:d7cf/64","169.254.215.207/16","fe80::d38:bbe6:7fc7:22df/64","192.168.99.1/24","240e:388:ba17:5800:11bd:fb54:4e2c:1075/64","240e:388:ba17:5800:79d5:7aba:a5e7:e923/128","fe80::11bd:fb54:4e2c:1075/64","192.168.1.8/24","fe80::6470:8ef2:6f21:4047/64","169.254.64.71/16","::1/128","127.0.0.1/8"],"kernel_version":"10.0.18362.836 (WinBuild.160101.0800)","mac":["9e:b6:d0:e8:71:d5","ae:b6:d0:e8:71:d5","00:50:56:c0:00:08","08:00:27:00:98:de","08:00:27:00:8c:19","9c:b6:d0:e8:71:d5","9c:b6:d0:e8:71:d6"],"os":{"family":"windows","platform":"windows","name":"Windows 10 Home China","version":"10.0","major":10,"minor":0,"patch":0,"build":"18362.836"},"timezone":"CST","timezone_offset_sec":28800,"id":"3b6ed37b-638a-487c-85bb-a7d70d9dd538"}}}
  2020-11-01T17:23:23.299+0800    INFO    [beat]  instance/beat.go:1021   Process info    {"system_info": {"process": {"cwd": "D:\\Application\\filebeat-7.9.3-windows-x86_64", "exe": "D:\\Application\\filebeat-7.9.3-windows-x86_64\\filebeat.exe", "name": "filebeat.exe", "pid": 46524, "ppid": 10268, "start_time": "2020-11-01T17:23:22.713+0800"}}}
  2020-11-01T17:23:23.299+0800    INFO    instance/beat.go:299    Setup Beat: filebeat; Version: 7.9.3
  2020-11-01T17:23:23.300+0800    INFO    [index-management]      idxmgmt/std.go:184      Set output.elasticsearch.index to 'filebeat-7.9.3' as ILM is enabled.
  2020-11-01T17:23:23.300+0800    INFO    eslegclient/connection.go:99    elasticsearch url: http://192.168.99.100:9200
  2020-11-01T17:23:23.301+0800    INFO    [publisher]     pipeline/module.go:113  Beat name: DESKTOP-OVSLAMI
  2020-11-01T17:23:23.303+0800    INFO    instance/beat.go:450    filebeat start running.
  2020-11-01T17:23:23.303+0800    INFO    [monitoring]    log/log.go:118  Starting metrics logging every 30s
  2020-11-01T17:23:23.304+0800    INFO    memlog/store.go:119     Loading data file of 'D:\Application\filebeat-7.9.3-windows-x86_64\data\registry\filebeat' succeeded. Active transaction id=0
  2020-11-01T17:23:23.304+0800    INFO    memlog/store.go:124     Finished loading transaction log file for 'D:\Application\filebeat-7.9.3-windows-x86_64\data\registry\filebeat'. Active transaction id=0
  2020-11-01T17:23:23.305+0800    INFO    [registrar]     registrar/registrar.go:109      States Loaded from registrar: 0
  2020-11-01T17:23:23.305+0800    INFO    [crawler]       beater/crawler.go:71    Loading Inputs: 1
  2020-11-01T17:23:23.333+0800    INFO    log/input.go:157        Configured paths: [D:\var\log\cron-booking\*]
  2020-11-01T17:23:23.334+0800    INFO    [crawler]       beater/crawler.go:141   Starting input (ID: 9141699098459531742)
  2020-11-01T17:23:23.335+0800    INFO    [crawler]       beater/crawler.go:108   Loading and starting Inputs completed. Enabled inputs: 1
  2020-11-01T17:23:23.335+0800    INFO    cfgfile/reload.go:164   Config reloader started
  2020-11-01T17:23:23.336+0800    INFO    cfgfile/reload.go:224   Loading of config files completed.
  2020-11-01T17:23:23.343+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-28-17.log
  2020-11-01T17:23:23.343+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-14.log
  2020-11-01T17:23:23.349+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-30-14.log
  2020-11-01T17:23:26.196+0800    INFO    [add_cloud_metadata]    add_cloud_metadata/add_cloud_metadata.go:89     add_cloud_metadata: hosting provider type not detected.
  2020-11-01T17:23:26.222+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\.4979870905f4c5cb6e5a898050c9d054817db5e9-audit.json
  2020-11-01T17:23:26.223+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-30-13.log
  2020-11-01T17:23:26.225+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-23-21.log
  2020-11-01T17:23:26.225+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-16.log
  2020-11-01T17:23:26.226+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-26-14.log
  2020-11-01T17:23:26.227+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-28-16.log
  2020-11-01T17:23:26.227+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-30-10.log
  2020-11-01T17:23:26.228+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-28-16.log
  2020-11-01T17:23:26.229+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-23-20.log
  2020-11-01T17:23:26.229+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-18.log
  2020-11-01T17:23:26.229+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-26-13.log
  2020-11-01T17:23:26.230+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-28-17.log
  2020-11-01T17:23:26.230+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-28-14.log
  2020-11-01T17:23:26.231+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-29-15.log
  2020-11-01T17:23:26.232+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-12.log
  2020-11-01T17:23:26.231+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-30-18.log
  2020-11-01T17:23:26.232+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-13.log
  2020-11-01T17:23:26.234+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-26-15.log
  2020-11-01T17:23:26.233+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-17.log
  2020-11-01T17:23:26.233+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-20.log
  2020-11-01T17:23:26.234+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-29-16.log
  2020-11-01T17:23:26.236+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-30-15.log
  2020-11-01T17:23:26.241+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-30-13.log
  2020-11-01T17:23:26.242+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\.a81bc33224b87e64d9d0e949864b48977fb93e8b-audit.json
  2020-11-01T17:23:26.243+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-30-10.log
  2020-11-01T17:23:26.243+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-30-17.log
  2020-11-01T17:23:26.243+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-21.log
  2020-11-01T17:23:26.244+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-28-14.log
  2020-11-01T17:23:26.244+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-29-15.log
  2020-11-01T17:23:26.245+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-30-11.log
  2020-11-01T17:23:26.245+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-30-17.log
  2020-11-01T17:23:26.245+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-09.log
  2020-11-01T17:23:26.246+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-10.log
  2020-11-01T17:23:26.246+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-11.log
  2020-11-01T17:23:26.247+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-24-21.log
  2020-11-01T17:23:26.248+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\access-2020-10-30-11.log
  2020-11-01T17:23:26.248+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-23-19.log
  2020-11-01T17:23:26.249+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-15.log
  2020-11-01T17:23:26.249+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-24-19.log
  2020-11-01T17:23:26.249+0800    INFO    log/harvester.go:299    Harvester started for file: D:\var\log\cron-booking\app-2020-10-26-13.log
  2020-11-01T17:23:27.223+0800    INFO    [publisher]     pipeline/retry.go:219   retryer: send unwait signal to consumer
  2020-11-01T17:23:27.224+0800    INFO    [publisher]     pipeline/retry.go:223     done
  2020-11-01T17:23:27.247+0800    INFO    [publisher_pipeline_output]     pipeline/output.go:143  Connecting to backoff(elasticsearch(http://192.168.99.100:9200))
  2020-11-01T17:23:27.259+0800    INFO    [esclientleg]   eslegclient/connection.go:314   Attempting to connect to Elasticsearch version 7.9.3
  2020-11-01T17:23:27.293+0800    INFO    [license]       licenser/es_callback.go:51      Elasticsearch license: Basic
  2020-11-01T17:23:27.295+0800    INFO    [esclientleg]   eslegclient/connection.go:314   Attempting to connect to Elasticsearch version 7.9.3
  2020-11-01T17:23:27.326+0800    INFO    [index-management]      idxmgmt/std.go:261      Auto ILM enable success.
  2020-11-01T17:23:27.478+0800    INFO    [index-management]      idxmgmt/std.go:274      ILM policy successfully loaded.
  2020-11-01T17:23:27.478+0800    INFO    [index-management]      idxmgmt/std.go:407      Set setup.template.name to '{filebeat-7.9.3 {now/d}-000001}' as ILM is enabled.
  2020-11-01T17:23:27.479+0800    INFO    [index-management]      idxmgmt/std.go:412      Set setup.template.pattern to 'filebeat-7.9.3-*' as ILM is enabled.
  2020-11-01T17:23:27.479+0800    INFO    [index-management]      idxmgmt/std.go:446      Set settings.index.lifecycle.rollover_alias in template to {filebeat-7.9.3 {now/d}-000001} as ILM is enabled.
  2020-11-01T17:23:27.480+0800    INFO    [index-management]      idxmgmt/std.go:450      Set settings.index.lifecycle.name in template to {filebeat {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"30d","max_size":"50gb"}}}}}}} as ILM is enabled.
  2020-11-01T17:23:27.482+0800    INFO    template/load.go:169    Existing template will be overwritten, as overwrite is enabled.
  2020-11-01T17:23:28.222+0800    INFO    template/load.go:109    Try loading template filebeat-7.9.3 to Elasticsearch
  2020-11-01T17:23:28.602+0800    INFO    template/load.go:101    template with name 'filebeat-7.9.3' loaded.
  2020-11-01T17:23:28.603+0800    INFO    [index-management]      idxmgmt/std.go:298      Loaded index template.
  2020-11-01T17:23:29.407+0800    INFO    [index-management]      idxmgmt/std.go:309      Write alias successfully generated.
  2020-11-01T17:23:29.408+0800    INFO    [publisher_pipeline_output]     pipeline/output.go:151  Connection to backoff(elasticsearch(http://192.168.99.100:9200)) established
  
  #...
  2020-11-01T17:33:53.305+0800    INFO    [monitoring]    log/log.go:145  Non-zero metrics in the last 30s        {"monitoring": {"metrics": {"beat":{"cpu":{"system":{"ticks":531,"time":{"ms":16}},"total":{"ticks":1827,"time":{"ms":31},"value":1827},"user":{"ticks":1296,"time":{"ms":15}}},"handles":{"open":232},"info":{"ephemeral_id":"afbfd966-c459-4c30-a3e7-123f1126ef84","uptime":{"ms":630405}},"memstats":{"gc_next":17504416,"memory_alloc":9783128,"memory_total":240521960,"rss":36864},"runtime":{"goroutines":34}},"filebeat":{"events":{"added":4,"done":4},"harvester":{"closed":2,"files":{"75cb8842-0883-4691-a6ac-2d831c052e1d":{"last_event_published_time":"","last_event_timestamp":"","name":"D:\\var\\log\\cron-booking\\.a81bc33224b87e64d9d0e949864b48977fb93e8b-audit.json","read_offset":2033,"size":2034,"start_time":"2020-11-01T17:33:46.654Z"},"e7cbcc8a-346e-4bdf-a52e-a9686ea26321":{"last_event_published_time":"","last_event_timestamp":"","name":"D:\\var\\log\\cron-booking\\.4979870905f4c5cb6e5a898050c9d054817db5e9-audit.json","read_offset":5825,"size":5826,"start_time":"2020-11-01T17:33:46.651Z"}},"open_files":2,"running":2,"started":2}},"libbeat":{"config":{"module":{"running":0}},"pipeline":{"clients":1,"events":{"active":0,"filtered":4,"total":4}}},"registrar":{"states":{"current":43,"update":4},"writes":{"success":4,"total":4}}}}}
  ```
