struct C2Request
{
  int s_usr_agent;
  int s_IP;
  int s_url;
  int s_HTTP_ver;
  int s_HTTP_verb;
  int is_post_req;
  int port;
  int force_download_from_origin;
  int s_post_data;
  int post_data_len;
  int http_rsp_data;
  int http_rsp_data_len;
};