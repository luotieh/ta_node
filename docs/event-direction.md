# 新事件方向判断（Schema 1.7）

本功能只在新告警创建时填写方向，不扫描历史数据库，不因后续角色识别改写已有事件的方向。原有请求/响应上下文修订继续运行，但保留触发包的方向字段。

`raw_packet` 新增 `direction_source`（protocol / handshake / session / unknown）、`direction_confidence`（high / medium / unknown）和 `transport_direction`（client_to_server / server_to_client / unknown）。`message_direction` 仍为 request / response / unknown。旧事件缺少新增字段时仍可读取。

协议直接识别沿用 HTTP 请求行、HTTP 响应行、DNS QR、TLS ClientHello SNI；TCP SYN 与 SYN+ACK 沿用原方向标签并注明 handshake。握手或协议证据确定 TCP 连接角色，矛盾证据会禁止后续角色推断，新的 SYN 建立新会话后重置。

启用 session 聚合时，已确认角色、已有 HTTP 事务且 Content-Length 边界可验证的正文续包可回填请求/响应，来源为 session，置信度为 medium。不会仅因端口号、首包发送方或连接角色推断应用消息方向。截断包、超出消息边界、chunked、升级协议、HEAD/CONNECT 响应、TLS 密文及纯 ACK/FIN/RST 不进行正文方向回填。TLS 密文和控制包仍可携带连接传输方向。

需要 `aggregation.mode: session` 和 `enable_transaction_link: true` 才能跨包推断；关闭时仅记录当前包的直接判断依据。页面新增判断依据与传输方向。管理平台应兼容 Schema 1.7 的可选字段。
