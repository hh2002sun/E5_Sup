import requests
import time
from urllib.parse import quote, urlencode, unquote
import pickle
import os
import json
from datetime import datetime

# --- 配置 ---
BASE_URL = ""
SIGN_IN_URL = f"{BASE_URL}/auth/sign-in"
CREDENTIALS_CALLBACK_URL = f"{BASE_URL}/api/auth/callback/credentials"
SESSION_API_URL = f"{BASE_URL}/api/auth/session"

PROJECT_ID = ""

COOKIE_FILE = "langfuse_cookies.pkl"
PERSISTENCE_DIR = "script_persistence"
PROCESSED_IDS_FILE = os.path.join(PERSISTENCE_DIR, "processed_trace_ids.json")
ALERTS_SUCCESS_HISTORY_FILE = os.path.join(PERSISTENCE_DIR, "wecom_alerts_successful.jsonl")
FAILED_ALERTS_HISTORY_FILE = os.path.join(PERSISTENCE_DIR, "wecom_alerts_failed.jsonl")
SAVE_TRPC_ERROR_LIST_SNAPSHOT = True
TRPC_SNAPSHOT_FILE = os.path.join(PERSISTENCE_DIR, "trpc_error_trace_list_latest.json")

WECOM_WEBHOOK_URL = "https://cgi-bin/webhook/send?"
APP_WORKFLOW_URL_TEMPLATE = "{app_id}/workflow"
WECOM_RETRY_ATTEMPTS = 5
WECOM_RETRY_DELAY_SECONDS = 3



HTML_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
}
JSON_REQUEST_HEADERS = {
    "Accept": "application/json, text/plain, */*", "Accept-Encoding": "gzip, deflate",
    "Accept-Language": HTML_HEADERS["Accept-Language"], "User-Agent": HTML_HEADERS["User-Agent"],
    "Content-Type": "application/json",
}


# --- 日志记录与持久化函数 ---
def log_wecom_alert_attempt(alert_data_dict, status, details=""):
    filepath = ALERTS_SUCCESS_HISTORY_FILE if status == "SUCCESS" else FAILED_ALERTS_HISTORY_FILE
    log_entry = {
        "log_timestamp": datetime.now().isoformat(),
        "status": status,
        "alert_details": alert_data_dict,
    }
    if details and status == "FAILED_ALL_RETRIES":
        log_entry["failure_reason"] = details
    try:
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"记录告警尝试到 {filepath} 失败: {e}")


def load_processed_ids(filepath):  # ... (与上一版相同)
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                ids = set(json.load(f))
            print(f"从 {filepath} 加载了 {len(ids)} 个已成功告警的 Trace ID。")
            return ids
        except Exception as e:
            print(f"加载已成功告警ID列表 '{filepath}' 失败: {e}。将使用空集合开始。")
    return set()


def save_processed_ids(ids_set, filepath):  # ... (与上一版相同)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(list(ids_set), f, indent=4)
        print(f"已成功告警的 Trace ID 列表已更新并保存到 {filepath} (共 {len(ids_set)} 个)")
    except Exception as e:
        print(f"保存已成功告警ID列表 '{filepath}' 失败: {e}")


# --- 企业微信通知函数 (带重试逻辑) ---
def send_wecom_notification(error_data):
    trace_id = error_data.get("trace_id", "N/A");
    error_reason = error_data.get("error_reason", "未知错误原因")
    error_time_str = error_data.get("error_time", "未知时间");
    app_workflow_url = error_data.get("app_workflow_url")
    try:
        formatted_time = datetime.fromisoformat(error_time_str.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        formatted_time = error_time_str
    content_lines = [f"Langfuse 告警：@all", f"> **追踪ID**: <font color=\"comment\">{trace_id}</font>",
                     f"> **时间**: <font color=\"comment\">{formatted_time}</font>",
                     f"> **原因**: <font color=\"warning\">{error_reason}</font>"]
    if app_workflow_url:
        content_lines.append(f"> **应用链接**: [点击查看工作流]({app_workflow_url})")
    else:
        content_lines.append("> **应用链接**: <font color=\"comment\">未能提取到应用ID</font>")
    payload = {"msgtype": "markdown", "markdown": {"content": "\n".join(content_lines)}}
    attempt_count = 0;
    last_exception_str = "无特定异常信息"
    while attempt_count < WECOM_RETRY_ATTEMPTS:
        attempt_count += 1
        print(f"  尝试第 {attempt_count}/{WECOM_RETRY_ATTEMPTS} 次发送企业微信通知 for Trace ID: {trace_id}")
        try:
            response = requests.post(WECOM_WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status();
            resp_json = response.json()
            if resp_json.get("errcode") == 0:
                print(f"    第 {attempt_count} 次尝试发送成功。"); return True
            else:
                last_exception_str = f"WeCom API Error: {resp_json.get('errmsg')} (errcode: {resp_json.get('errcode')})"; print(
                    f"    第 {attempt_count} 次尝试发送失败: {last_exception_str}")
        except requests.exceptions.SSLError as ssl_err:
            last_exception_str = str(ssl_err); print(f"    第 {attempt_count} 次 SSL 错误: {ssl_err}")
        except requests.exceptions.Timeout:
            last_exception_str = "请求超时"; print(f"    第 {attempt_count} 次尝试发送超时。")
        except requests.exceptions.RequestException as req_err:
            last_exception_str = str(req_err); print(f"    第 {attempt_count} 次网络错误: {req_err}")
        except Exception as e_gen:
            last_exception_str = str(e_gen); print(f"    第 {attempt_count} 次未知错误: {e_gen}")
        if attempt_count < WECOM_RETRY_ATTEMPTS:
            print(f"    等待 {WECOM_RETRY_DELAY_SECONDS} 秒后重试..."); time.sleep(WECOM_RETRY_DELAY_SECONDS)
        else:
            print(f"  所有 {WECOM_RETRY_ATTEMPTS} 次发送尝试均失败 for Trace ID: {trace_id}"); log_wecom_alert_attempt(
                error_data, "FAILED_ALL_RETRIES", last_exception_str); return False
    return False


# --- Cookie, Session, Login 函数 (与之前版本相同) ---
def save_cookies_to_disk(session_cookies, filepath):  # ... (保持不变)
    try:
        with open(filepath, 'wb') as f:
            pickle.dump(session_cookies, f)
        print(f"Cookies 已保存到 {filepath}")
    except Exception as e:
        print(f"保存 Cookies 失败: {e}")


def load_cookies_from_disk(filepath):  # ... (保持不变)
    if os.path.exists(filepath):
        try:
            with open(filepath, 'rb') as f:
                cookies = pickle.load(f)
            print(f"Cookies 已从 {filepath} 加载。")
            return cookies
        except Exception as e:
            print(f"加载 Cookies {filepath} 失败: {e}")
            try:
                os.remove(filepath); print(f"已删除损坏的 cookie 文件: {filepath}")
            except OSError as ose:
                print(f"删除损坏的 cookie 文件 {filepath} 失败: {ose}")
    return None


def check_session_is_valid(session):  # ... (保持不变)
    print("正在验证当前 session...")
    check_headers = JSON_REQUEST_HEADERS.copy();
    check_headers["Referer"] = BASE_URL
    try:
        response = session.get(SESSION_API_URL, headers=check_headers, timeout=10)
        if response.status_code == 200:
            session_data = response.json()
            if session_data and session_data.get("user"):
                print(f"Session 有效。用户信息: {session_data.get('user', {}).get('email', 'N/A')}")
                return True
            else:
                print(f"Session API 响应200但内容不符。响应: {str(session_data)[:200]}..."); return False
        elif response.status_code == 401:
            print("Session 无效 (401 Unauthorized)。"); return False
        else:
            print(f"Session 验证返回码: {response.status_code}"); return False
    except Exception as e:
        print(f"Session 验证失败: {e}"); return False


def login_to_langfuse(session):  # ... (与之前版本相同)
    print("执行登录流程...")
    html_req_headers = HTML_HEADERS.copy()
    try:
        print(f"正在初步访问登录页面: {SIGN_IN_URL}")
        initial_signin_response = session.get(SIGN_IN_URL, headers=html_req_headers, timeout=15, allow_redirects=True)
        initial_signin_response.raise_for_status()
        final_signin_page_url = initial_signin_response.url
        print(f"初步访问登录页面成功。最终 URL: {final_signin_page_url}")

        print(f"正在调用 session API ({SESSION_API_URL}) 获取CSRF token...")
        session_api_headers = JSON_REQUEST_HEADERS.copy();
        session_api_headers["Referer"] = final_signin_page_url
        session_api_response = session.get(SESSION_API_URL, headers=session_api_headers, timeout=15)
        session_api_response.raise_for_status()
        print(f"调用 session API 成功。状态码: {session_api_response.status_code}")

        csrf_token_for_form = None
        for cookie in session.cookies:
            if 'csrf-token' in cookie.name.lower(): csrf_token_for_form = unquote(cookie.value).split('|')[0]; break
        if not csrf_token_for_form:
            print("Cookie中未找到CSRF token，尝试从session API响应中获取...")
            try:
                session_data_for_csrf = session_api_response.json()
                if isinstance(session_data_for_csrf, dict) and "csrfToken" in session_data_for_csrf:
                    csrf_token_for_form = session_data_for_csrf["csrfToken"]
                else:
                    print("session API JSON响应中未找到csrfToken。"); return False
            except ValueError:
                print("session API响应不是有效JSON。"); return False
        if not csrf_token_for_form: print("错误: 未能获取CSRF token。"); return False
        print(f"提取到CSRF token: {csrf_token_for_form}")

        login_payload = {"email": EMAIL, "password": PASSWORD, "callbackUrl": "/", "redirect": "false",
                         "turnstileToken": "undefined", "csrfToken": csrf_token_for_form, "json": "true"}
        post_headers = HTML_HEADERS.copy();
        post_headers["Content-Type"] = "application/x-www-form-urlencoded";
        post_headers["Origin"] = BASE_URL.rstrip('/');
        post_headers["Referer"] = final_signin_page_url
        print(f"发送登录 POST 请求至 {CREDENTIALS_CALLBACK_URL}...")
        login_response = session.post(CREDENTIALS_CALLBACK_URL, data=login_payload, headers=post_headers, timeout=15)
        login_response.raise_for_status()
        if not any(cookie.name == 'next-auth.session-token' for cookie in session.cookies):
            print("登录失败: 未找到 'next-auth.session-token'。");
            return False
        print("登录成功!")
        return True
    except Exception as e:
        print(f"登录过程中发生错误: {e}"); return False


# --- 函数：处理指定的错误追踪列表，提取告警数据 ---
def extract_alert_data_for_new_traces(session, new_trace_items_to_process_detail):
    # (函数体与上一版相同，包含 "Stopped by user." 过滤 和 app_id 提取逻辑)
    # 此函数不再保存任何单个JSON文件，也不再负责更新 processed_trace_ids
    alerts_to_send = []
    if not new_trace_items_to_process_detail: return alerts_to_send
    print(f"  对 {len(new_trace_items_to_process_detail)} 个新条目进行详细信息提取...")

    for trace_item in new_trace_items_to_process_detail:
        trace_id = trace_item.get("id");
        trace_timestamp = trace_item.get("timestamp")
        if not trace_id or not trace_timestamp: print(f"    警告: 详细处理时发现条目缺少必要ID。跳过。"); continue

        input_trace_detail = {"json": {"traceId": trace_id, "projectId": PROJECT_ID, "timestamp": trace_timestamp},
                              "meta": {"values": {"timestamp": ["Date"]}}}
        encoded_input_trace_detail = quote(json.dumps(input_trace_detail))
        trace_detail_api_url = f"{BASE_URL}/api/trpc/traces.byIdWithObservationsAndScores?input={encoded_input_trace_detail}"

        print(f"    获取 Trace 详细数据 (ID: {trace_id})")
        status_message = None;
        app_id_found = None;
        error_specific_time = trace_timestamp

        try:
            detail_req_headers = JSON_REQUEST_HEADERS.copy();
            detail_req_headers["Referer"] = f"{BASE_URL}/project/{PROJECT_ID}/traces/{trace_id}"
            detail_response = session.get(trace_detail_api_url, headers=detail_req_headers, timeout=20)
            detail_response.raise_for_status()
            if "application/json" not in detail_response.headers.get("Content-Type", "").lower():
                print(f"      错误: Trace Detail URL 未返回JSON。");
                continue

            trace_detail_json_data_full = detail_response.json()
            actual_trace_data = None
            if trace_detail_json_data_full.get("result") and trace_detail_json_data_full["result"].get("data") and \
                    isinstance(trace_detail_json_data_full["result"]["data"].get("json"), dict):
                actual_trace_data = trace_detail_json_data_full["result"]["data"]["json"]
            if not actual_trace_data: print(f"      无法从 {trace_id} 的详细数据中解析出核心 'json' 对象。"); continue

            for key_to_check in ["input", "metadata"]:  # 提取 app_id
                if app_id_found: break
                field_content_str = actual_trace_data.get(key_to_check)
                if isinstance(field_content_str, str):
                    try:
                        nested_json = json.loads(field_content_str)
                        if isinstance(nested_json, dict): app_id_found = nested_json.get("app_id") or nested_json.get(
                            "sys.app_id")
                    except json.JSONDecodeError:
                        pass

            if "workflow" in actual_trace_data.get("tags", []):
                for obs_in_list in actual_trace_data.get("observations", []):
                    if isinstance(obs_in_list, dict) and obs_in_list.get("level") == "ERROR":
                        obs_id_for_byid = obs_in_list.get("id");
                        obs_starttime_for_byid = obs_in_list.get("startTime")
                        if not obs_id_for_byid or not obs_starttime_for_byid: continue
                        input_obs_by_id = {
                            "json": {"observationId": obs_id_for_byid, "startTime": obs_starttime_for_byid,
                                     "traceId": trace_id, "projectId": PROJECT_ID},
                            "meta": {"values": {"startTime": ["Date"]}}}
                        encoded_input_obs_by_id = quote(json.dumps(input_obs_by_id))
                        obs_by_id_url = f"{BASE_URL}/api/trpc/observations.byId?input={encoded_input_obs_by_id}"
                        try:
                            obs_by_id_resp = session.get(obs_by_id_url, headers=JSON_REQUEST_HEADERS, timeout=15)
                            obs_by_id_resp.raise_for_status()
                            if "application/json" not in obs_by_id_resp.headers.get("Content-Type",
                                                                                    "").lower(): continue
                            specific_obs_json_full = obs_by_id_resp.json()
                            specific_obs_data = None
                            if specific_obs_json_full.get("result") and specific_obs_json_full["result"].get("data") and \
                                    isinstance(specific_obs_json_full["result"]["data"].get("json"), dict):
                                specific_obs_data = specific_obs_json_full["result"]["data"]["json"]
                            if specific_obs_data:
                                if not app_id_found:
                                    for obs_key_to_check in ["input", "metadata"]:
                                        if app_id_found: break
                                        obs_field_content_str = specific_obs_data.get(obs_key_to_check)
                                        if isinstance(obs_field_content_str, str):
                                            try:
                                                obs_nested_json = json.loads(obs_field_content_str)
                                                if isinstance(obs_nested_json,
                                                              dict): app_id_found = obs_nested_json.get(
                                                    "app_id") or obs_nested_json.get("sys.app_id")
                                            except json.JSONDecodeError:
                                                pass
                                if isinstance(specific_obs_data.get("output"), str):
                                    try:
                                        output_json = json.loads(specific_obs_data["output"])
                                        if isinstance(output_json, dict) and "error_message" in output_json:
                                            status_message = output_json["error_message"];
                                            error_specific_time = obs_starttime_for_byid;
                                            break
                                    except json.JSONDecodeError:
                                        pass
                                elif specific_obs_data.get("statusMessage"):
                                    status_message = specific_obs_data.get("statusMessage");
                                    error_specific_time = obs_starttime_for_byid;
                                    break
                        except Exception:
                            pass

            if not status_message:  # 通用提取
                if "metadata" in actual_trace_data and isinstance(actual_trace_data["metadata"], str):
                    try:
                        trace_metadata = json.loads(actual_trace_data["metadata"])
                        if isinstance(trace_metadata, dict) and trace_metadata.get("status") and \
                                ("fail" in trace_metadata["status"].lower() or "error" in trace_metadata[
                                    "status"].lower() or "partial-succeeded" in trace_metadata["status"].lower()):
                            status_message = f"Trace Metadata Status: {trace_metadata['status']}"
                    except json.JSONDecodeError:
                        pass
                if not status_message and "observations" in actual_trace_data:
                    for obs in actual_trace_data.get("observations", []):
                        if isinstance(obs, dict):
                            obs_level = str(obs.get("level", "")).upper();
                            obs_status_code = str(obs.get("statusCode", "")).upper()
                            current_obs_message = None;
                            obs_time = obs.get("startTime", error_specific_time)
                            if obs_level == "ERROR":
                                current_obs_message = obs.get("statusMessage", "") or f"Level:ERROR(ID:{obs.get('id')})"
                                error_specific_time = obs_time
                            elif obs_status_code == "ERROR":
                                current_obs_message = obs.get("statusMessage",
                                                              "") or f"StatusCode:ERROR(ID:{obs.get('id')})"
                                error_specific_time = obs_time
                            if not current_obs_message and "output" in obs and isinstance(obs["output"], dict) and obs[
                                "output"].get("error"):
                                current_obs_message = obs['output']['error']
                                error_specific_time = obs_time
                            if current_obs_message: status_message = current_obs_message; break

            final_alertable_message = None
            if status_message:
                if "Stopped by user." in status_message:
                    print(f"    已过滤掉用户停止类型的错误消息: '{status_message}' (Trace ID {trace_id})")
                else:
                    final_alertable_message = status_message

            if final_alertable_message:
                app_workflow_url = APP_WORKFLOW_URL_TEMPLATE.format(app_id=app_id_found) if app_id_found else None
                if app_id_found: print(f"    提取到 app_id: {app_id_found}")
                alerts_to_send.append({
                    "trace_id": trace_id, "error_reason": final_alertable_message,
                    "error_time": error_specific_time, "app_workflow_url": app_workflow_url
                })
                print(f"    准备告警: Trace ID {trace_id}, Reason: {final_alertable_message[:50]}...")
            else:
                print(f"    未能在 Trace ID {trace_id} 的详细数据中找到可告警的状态消息 (或已被过滤)。")
        except Exception as e_detail:
            print(f"    处理 Trace Detail (ID: {trace_id}) 时发生未知错误: {e_detail}")
        time.sleep(0.2)
    return alerts_to_send


# --- 主监控逻辑 ---
if __name__ == "__main__":
    session = requests.Session()
    session_active = False

    if not os.path.exists(PERSISTENCE_DIR):
        try:
            os.makedirs(PERSISTENCE_DIR); print(f"已创建目录: {PERSISTENCE_DIR}")
        except OSError as e:
            print(f"创建目录 {PERSISTENCE_DIR} 失败: {e}"); exit()

    processed_trace_ids = load_processed_ids(PROCESSED_IDS_FILE)

    loaded_cookies = load_cookies_from_disk(COOKIE_FILE)
    if loaded_cookies:
        session.cookies.update(loaded_cookies);
        if check_session_is_valid(session):
            print("使用已保存的有效 session。"); session_active = True
        else:
            print("已保存的 session 无效或已过期。"); session.cookies.clear()
    else:
        print("未找到本地保存的 session cookies。")

    if not session_active:
        print("需要登录。")
        if login_to_langfuse(session):
            save_cookies_to_disk(session.cookies, COOKIE_FILE); session_active = True
        else:
            print("\n登录失败。脚本无法继续。");
            send_wecom_notification({"error_reason": "脚本无法登录到 Langfuse"});
            exit()
    if not session_active: print("无法建立有效会话，脚本退出。"); exit()

    print("\nSession 有效。启动错误轮询监控...")
    try:
        while True:
            print(f"\n--- [{time.strftime('%Y-%m-%d %H:%M:%S')}] 开始新一轮错误检查 ---")
            trpc_input_traces_all = {
                "json": {"projectId": PROJECT_ID,
                         "filter": [{"column": "Error Level Count", "operator": ">", "value": 0, "type": "number"},
                                    {"column": "Timestamp", "type": "datetime", "operator": ">=",
                                     "value": "2025-05-15T06:56:00.150Z"},
                                    {"type": "stringOptions", "column": "environment", "operator": "any of",
                                     "value": ["default"]}],
                         "searchQuery": "", "searchType": ["id", "content"], "page": 0, "limit": 50,
                         "orderBy": {"column": "timestamp", "order": "DESC"}
                         }, "meta": {"values": {"filter.1.value": ["Date"]}}}
            encoded_input_traces_all = quote(json.dumps(trpc_input_traces_all))
            error_list_api_url = f"{BASE_URL}/api/trpc/traces.all?input={encoded_input_traces_all}"

            current_trace_items_from_api = []
            try:
                print(f"正在从 {error_list_api_url} 获取错误列表...")
                list_headers = JSON_REQUEST_HEADERS.copy();
                list_headers["Referer"] = f"{BASE_URL}/project/{PROJECT_ID}/traces"
                list_response = session.get(error_list_api_url, headers=list_headers, timeout=20)
                list_response.raise_for_status()
                if "application/json" not in list_response.headers.get("Content-Type", "").lower():
                    print(f"错误: traces.all API 未返回JSON。")
                else:
                    response_data_traces_all = list_response.json()
                    if (response_data_traces_all.get("result") and response_data_traces_all["result"].get("data") and \
                            response_data_traces_all["result"]["data"].get("json") and \
                            isinstance(response_data_traces_all["result"]["data"]["json"].get("traces"), list)):
                        current_trace_items_from_api = response_data_traces_all["result"]["data"]["json"]["traces"]
                        print(f"获取到 {len(current_trace_items_from_api)} 个当前错误追踪。")
                        if SAVE_TRPC_ERROR_LIST_SNAPSHOT:
                            with open(TRPC_SNAPSHOT_FILE, 'w', encoding='utf-8') as f:
                                json.dump(response_data_traces_all, f, ensure_ascii=False, indent=4)
                    else:
                        print("错误: traces.all API 返回的JSON结构不符合预期。")
            except Exception as e_list:
                print(f"获取错误列表时发生错误: {e_list}")

            new_traces_to_process_details = []
            if current_trace_items_from_api:
                for item in current_trace_items_from_api:
                    item_id = item.get("id")
                    if item_id and item_id not in processed_trace_ids:
                        new_traces_to_process_details.append(item)

            if new_traces_to_process_details:
                print(f"发现 {len(new_traces_to_process_details)} 个新的错误追踪需要进行详细处理。")
                # 这些是需要提取详情的，其ID尚未被永久标记为已处理（除非企微发送成功）
                alerts_data_list = extract_alert_data_for_new_traces(session, new_traces_to_process_details)

                if alerts_data_list:
                    print(f"\n准备为 {len(alerts_data_list)} 条有效新错误尝试发送企业微信通知 (带重试):")
                    ids_successfully_alerted_this_cycle = set()
                    for alert_data_item in alerts_data_list:
                        if send_wecom_notification(alert_data_item):  # send_wecom_notification 现在包含重试和失败日志记录
                            log_wecom_alert_attempt(alert_data_item, "SUCCESS")  # 记录成功的尝试
                            ids_successfully_alerted_this_cycle.add(alert_data_item["trace_id"])
                        # 如果 send_wecom_notification 返回 False, 失败日志已在内部记录

                    if ids_successfully_alerted_this_cycle:
                        processed_trace_ids.update(ids_successfully_alerted_this_cycle)
                        save_processed_ids(processed_trace_ids, PROCESSED_IDS_FILE)  # 保存更新后的已成功告警ID列表
                        print(
                            f"本轮成功告警 {len(ids_successfully_alerted_this_cycle)} 个新错误。已处理ID集合总数: {len(processed_trace_ids)}")
                else:
                    print("处理了新的错误追踪，但没有产生需要发送的告警 (所有新错误可能都被过滤掉了)。")
            else:
                print("没有发现新的错误追踪 (基于已成功告警的ID列表)。")

            print(f"等待 {POLLING_INTERVAL_SECONDS} 秒后进行下一轮检查...")
            time.sleep(POLLING_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n监控已手动停止。")
    except Exception as e_main_loop:
        print(f"监控主循环中发生致命错误: {e_main_loop}")
        send_wecom_notification({"error_reason": f"监控脚本发生致命错误: {e_main_loop}",
                                 "trace_id": "N/A_SCRIPT_ERROR", "error_time": datetime.now().isoformat()})