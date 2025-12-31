#include "frida-gum.h"
#include "hookUtils.h"
#include "logger.h"
#include "vm.h"
#include <cstdint>
#include <cstring>
#include <jni.h>
#include <sstream>
#include <string>
#include <thread>

static std::string m_so_path;

void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q) {

  if (F2Q) {
    for (int i = 0; i < 29; i++) {
      QBDI_GPR_SET(state, i, cpu->x[i]);
    }
    state->lr = cpu->lr;
    state->sp = cpu->sp;
    state->x29 = cpu->fp;
    state->nzcv = cpu->nzcv;

  } else {
    for (int i = 0; i < 29; i++) {
      cpu->x[i] = QBDI_GPR_GET(state, i);
    }
    cpu->fp = state->x29;
    cpu->lr = state->lr;
    cpu->sp = state->sp;
    cpu->nzcv = state->nzcv;
  }
}

bool isTraceAll = false;

// hook
HOOK_DEF(QBDI::rword, gum_handle) {
  LOGS("begin");
  clock_t start, end;
  start = clock();
  auto context = gum_interceptor_get_current_invocation();
  auto interceptor =
      (GumInterceptor *)gum_invocation_context_get_replacement_data(context);
  gum_interceptor_revert(interceptor, context->function);
  gum_interceptor_flush(interceptor);
  auto vm_ = new vm();
  auto qvm = vm_->init(context->function, isTraceAll);
  auto state = qvm.getGPRState();
  syn_reg_gum(context->cpu_context, state, true);
  uint8_t *fakestack;
  QBDI::allocateVirtualStack(state, STACK_SIZE, &fakestack);
  QBDI::rword ret;
  qvm.switchStackAndCall(&ret, (QBDI::rword)context->function);
  syn_reg_gum(context->cpu_context, state, false);
  end = clock();
  LOGS("time: %f", (double)(end - start) / CLOCKS_PER_SEC);
  LOGS("end");
  return ret;
}

// export
extern "C" void _init(void) { gum_init_embedded(); }
extern "C" {
__attribute__((visibility("default"))) void attd(void *target_addr) {
  LOGD("hooking %p", target_addr);
  hookUtils::gum_replace(target_addr, (void *)new_gum_handle,
                         (void **)(&orig_gum_handle));
}

__attribute__((visibility("default"))) void attd_trace(void *addr,
                                                       bool trace_all) {
  isTraceAll = trace_all;
  attd(addr);
}
void attd_call(void *target_addr, int argNum, ...) {
  LOGS("attd_call start %p", target_addr);
  uint8_t *fakestack;
  auto vm_ = new vm();
  auto qvm = vm_->init(target_addr);
  auto state = qvm.getGPRState();
  QBDI::allocateVirtualStack(state, STACK_SIZE, &fakestack);
  QBDI::rword ret;
  va_list args;
  va_start(args, argNum);
  va_list ap;
  qvm.callV(&ret, (QBDI::rword)target_addr, argNum, ap);
  va_end(args);

  LOGS("attd_call end %p", target_addr);
}
}

enum ATTD_MODE {
    ATTD_MODE_HOOK,
    ATTD_MODE_CALL,
};
static struct AttdConfig {
  bool available;
  char* target_so;
  uintptr_t address;
  int hook_delay;
  ATTD_MODE mode; // ATTD_MODE_HOOK or ATTD_MODE_CALL
  int argNum;
  uintptr_t args[10]; // args for call
} _config;


void init_attd_config_from_file(const char* f){
    
    // 文件内容格式
    // 当mode为hook字符串时 target_so|address|hook_delay|mode  
    // 当mode为call字符串时，参数按行读取argNum个
    // target_so|address|hook_delay|mode|argNum
    // arg1
    // arg2
    // arg3
    // arg4
    // arg5
    // arg6
    // arg7
    // arg8
    // arg9
    // arg10
    // 注意：mode字符串会被转换为ATTD_MODE枚举值
    
    // 辅助函数：检查字符串是否为空或只有空白字符
    auto is_valid_string = [](const std::string& str) -> bool {
        return !str.empty() && str.find_first_not_of(" \t\n\r") != std::string::npos;
    };
    
    // 辅助函数：安全转换字符串到无符号长整型
    auto safe_stoull = [](const std::string& str, size_t* pos = nullptr, int base = 16) -> uintptr_t {
        try {
            return std::stoull(str, pos, base);
        } catch (const std::exception& e) {
            LOGE("数值转换失败: %s -> %s", str.c_str(), e.what());
            return 0;
        }
    };
    
    // 辅助函数：安全转换字符串到整型
    auto safe_stoi = [](const std::string& str, size_t* pos = nullptr, int base = 10) -> int {
        try {
            return std::stoi(str, pos, base);
        } catch (const std::exception& e) {
            LOGE("数值转换失败: %s -> %s", str.c_str(), e.what());
            return -1;
        }
    };
    
    FILE *file = fopen64(f, "r");
    if (file == nullptr) {
        LOGE("配置文件打开失败: %s", f);
        return;
    }
    
    // 读取第一行配置
    char buf[1024];
    if (fgets(buf, sizeof(buf), file) == nullptr) {
        LOGE("配置文件读取失败");
        fclose(file);
        return;
    }
    
    LOGD("配置内容: %s", buf);
    std::string line(buf);
    std::stringstream ss(line);
    std::string token;
    
    // 解析target_so
    std::getline(ss, token, '|');
    if (!is_valid_string(token)) {
        LOGE("配置文件格式错误: target_so字段为空或无效");
        fclose(file);
        return;
    }
    _config.target_so = strdup(token.c_str());
    
    // 解析address
    std::getline(ss, token, '|');
    if (!is_valid_string(token)) {
        LOGE("配置文件格式错误: address字段为空或无效");
        fclose(file);
        return;
    }
    _config.address = safe_stoull(token, nullptr, 16);
    if (_config.address == 0) {
        LOGE("配置文件格式错误: address转换失败或为0");
        fclose(file);
        return;
    }
    
    // 解析hook_delay
    std::getline(ss, token, '|');
    if (!is_valid_string(token)) {
        LOGE("配置文件格式错误: hook_delay字段为空或无效");
        fclose(file);
        return;
    }
    _config.hook_delay = safe_stoi(token);
    if (_config.hook_delay < 0) {
        LOGE("配置文件格式错误: hook_delay不能为负数");
        fclose(file);
        return;
    }
    
    // 解析mode
    std::getline(ss, token, '|');
    if (!is_valid_string(token)) {
        LOGE("配置文件格式错误: mode字段为空或无效");
        fclose(file);
        return;
    }
    
    // 将字符串转换为枚举值
    if (token == "hook") {
        _config.mode = ATTD_MODE_HOOK;
    } else if (token == "call") {
        _config.mode = ATTD_MODE_CALL;
    } else {
        LOGE("配置文件格式错误: mode必须是'hook'或'call'");
        fclose(file);
        return;
    }
    
    // 如果是call模式，读取argNum和后续参数
    if (_config.mode == ATTD_MODE_CALL) {
        std::getline(ss, token, '|');
        if (!is_valid_string(token)) {
            LOGE("配置文件格式错误: call模式缺少argNum参数");
            fclose(file);
            return;
        }
        _config.argNum = safe_stoi(token);
        if (_config.argNum < 0 || _config.argNum > 10) {
            LOGE("配置文件格式错误: argNum必须在0-10范围内");
            fclose(file);
            return;
        }
        
        // 读取后续的参数行
        for (int i = 0; i < _config.argNum; i++) {
            if (fgets(buf, sizeof(buf), file) == nullptr) {
                LOGE("配置文件格式错误: 缺少参数arg%d", i+1);
                fclose(file);
                return;
            }
            std::string arg_line(buf);
            // 去除换行符
            if (!arg_line.empty() && arg_line.back() == '\n') {
                arg_line.pop_back();
            }
            if (!is_valid_string(arg_line)) {
                LOGE("配置文件格式错误: arg%d参数为空或无效", i+1);
                fclose(file);
                return;
            }
            _config.args[i] = safe_stoull(arg_line, nullptr, 16);
        }
    }
    
    fclose(file);
    _config.available = true;
    LOGD("配置文件解析成功");
}
void *sub_thread(AttdConfig *config) {

  // std::this_thread::sleep_for(std::chrono::seconds(_config.hook_delay));

  LOGD("config: %s %lx %d mode: %d", config->target_so, config->address,
       config->hook_delay, config->mode);
  sleep(config->hook_delay);

  auto base = getSoBaseAddress(config->target_so).start;
  LOGD("%s base: %lx", config->target_so, base);
  if (base != 0) {
    void *target_addr = (void *)(base + config->address);
    
    if (config->mode == ATTD_MODE_HOOK) {
      // hook模式：使用attd函数
      LOGD("使用hook模式，调用attd函数");
      attd(target_addr);
    } else if (config->mode == ATTD_MODE_CALL) {
      // call模式：使用attd_call函数
      LOGD("使用call模式，调用attd_call函数，参数数量: %d", config->argNum);
      
      // 根据argNum的值传递对应的参数
      switch (config->argNum) {
        case 0:
          attd_call(target_addr, 0);
          break;
        case 1:
          attd_call(target_addr, 1, config->args[0]);
          break;
        case 2:
          attd_call(target_addr, 2, config->args[0], config->args[1]);
          break;
        case 3:
          attd_call(target_addr, 3, config->args[0], config->args[1], config->args[2]);
          break;
        case 4:
          attd_call(target_addr, 4, config->args[0], config->args[1], config->args[2], config->args[3]);
          break;
        case 5:
          attd_call(target_addr, 5, config->args[0], config->args[1], config->args[2], config->args[3], config->args[4]);
          break;
        case 6:
          attd_call(target_addr, 6, config->args[0], config->args[1], config->args[2], config->args[3], config->args[4], config->args[5]);
          break;
        case 7:
          attd_call(target_addr, 7, config->args[0], config->args[1], config->args[2], config->args[3], config->args[4], config->args[5], config->args[6]);
          break;
        case 8:
          attd_call(target_addr, 8, config->args[0], config->args[1], config->args[2], config->args[3], config->args[4], config->args[5], config->args[6], config->args[7]);
          break;
        case 9:
          attd_call(target_addr, 9, config->args[0], config->args[1], config->args[2], config->args[3], config->args[4], config->args[5], config->args[6], config->args[7], config->args[8]);
          break;
        case 10:
          attd_call(target_addr, 10, config->args[0], config->args[1], config->args[2], config->args[3], config->args[4], config->args[5], config->args[6], config->args[7], config->args[8], config->args[9]);
          break;
        default:
          LOGE("不支持的参数数量: %d", config->argNum);
          break;
      }
    } else {
      LOGE("不支持的mode值: %d", config->mode);
    }
  }
  return nullptr;
}

__unused __attribute__((constructor)) void init_main() {
  LOGD("load attd ok !!");
  Dl_info info;
  dladdr((void *)init_main, &info);
  m_so_path = info.dli_fname;

  if (m_so_path.empty()) {
    LOGD("m_so_path is empty");
  } else {
    LOGD("m_so_path: %s", m_so_path.c_str());
    auto config_path = m_so_path + ".config";
    if (access(config_path.c_str(), F_OK) == 0) {
      init_attd_config_from_file(config_path.c_str());
      if (_config.available) {

        //.config 文件内容 为 target_so|address|hook_delay|("call|hook") 实例化 _config


        std::thread t(sub_thread, &_config);
        t.detach();

      } else {
        LOGD("config file open failed");
      }

    } else {
      LOGD("config file not exist");
    }
  }
}