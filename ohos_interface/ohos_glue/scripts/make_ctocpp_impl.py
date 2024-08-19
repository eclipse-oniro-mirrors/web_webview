#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import

import os
import file_parser
import make_file_base

# pylint:disable=variable-type-changed
# pylint:disable=huawei-redefined-outer-name

def make_ctocpp_impl_proto(clsname, name, func, parts):
  const = ''
  proto = 'ARK_WEB_NO_SANITIZE\n'
  if clsname is None:
    proto += 'ARK_WEB_GLOBAL ' + parts['retval'] + ' ' + name + '(' + ', '.join(parts['args']) + ')' + const
  else:
    proto += parts['retval'] + ' ' + clsname
    if isinstance(func, file_parser.obj_function_virtual):
      proto += 'CToCpp'
      if func.is_const():
        const = ' const'
    proto += '::' + name + '(' + ', '.join(parts['args']) + ')' + const

  return proto

def verify_ctocpp_func_args(func, retval_default):
  result = ''
  args = func.get_arguments()
  for arg in args:
    arg_type = arg.get_arg_type()
    arg_name = arg.get_type().get_name()
    comment = '\n  // Verify param: ' + arg_name + '; type: ' + arg_type

    if arg_type == 'bool_byaddr':
      result += comment + \
                '\n  if (!' + arg_name + ') {'\
                '\n    return' + retval_default + ';'\
                '\n  }'

    # check index params
    index_params = arg.parent.get_attrib_list('index_param')
    if not index_params is None and arg_name in index_params:
      result += comment + \
                '\n  if (' + arg_name + ' < 0) {'\
                '\n    return' + retval_default + ';'\
                '\n  }'
  return result

def restore_ctocpp_func_args(func):
  result = ''
  args = func.get_arguments()
  for arg in args:
    arg_type = arg.get_arg_type()
    arg_name = arg.get_type().get_name()
    comment = '\n  // Restore param:' + arg_name + '; type: ' + arg_type

    if arg_type == 'bool_byaddr':
      result += comment + \
                '\n  if (' + arg_name + ') {'\
                '\n    *' + arg_name + ' = ' + arg_name + 'Int ? true : false;'\
                '\n  }'
    elif arg_type == 'refptr_same_byref' or arg_type == 'refptr_diff_byref':
      ptr_class = arg.get_type().get_ptr_type()
      if arg_type == 'refptr_same_byref':
        assign = ptr_class + 'CToCpp::Invert(' + arg_name + 'Struct)'
      else:
        assign = ptr_class + 'CppToC::Revert(' + arg_name + 'Struct)'
      result += comment + \
                '\n  if (' + arg_name + 'Struct) {'\
                '\n    if (' + arg_name + 'Struct != ' + arg_name + 'Orig) {'\
                '\n      ' + arg_name + ' = ' + assign + ';'\
                '\n    }'\
                '\n  } else {'\
                '\n    ' + arg_name + ' = nullptr;'\
                '\n  }'
  return result;

def translate_ctocpp_func_args(func):
  params = []
  if isinstance(func, file_parser.obj_function_virtual):
    params.append('_struct')

  result = ''
  args = func.get_arguments()
  for arg in args:
    arg_type = arg.get_arg_type()
    arg_name = arg.get_type().get_name()
    comment = '\n  // Translate param: ' + arg_name + '; type: ' + arg_type

    if arg_type == 'simple_byval' or arg_type == 'simple_byaddr' or \
       arg_type == 'bool_byval':
      if arg_name[0] == '*':
        params.append(arg_name[1:])
      else:
        pos = arg_name.find('[')
        if pos == -1:
          params.append(arg_name)
        else:
          params.append(arg_name[0:pos])
    elif arg_type == 'simple_byref' or arg_type == 'simple_byref_const' or \
        arg_type == 'struct_byref_const' or arg_type == 'struct_byref':
      params.append('&' + arg_name)
    elif arg_type == 'bool_byref':
      params.append('&' + arg_name)
    elif arg_type == 'bool_byaddr':
      result += comment + \
                '\n  int ' + arg_name + 'Int = ' + arg_name + '?*' + arg_name + ':0;'
      params.append('&' + arg_name + 'Int')
    elif arg_type == 'refptr_same':
      ptr_class = arg.get_type().get_ptr_type()
      params.append(ptr_class + 'CToCpp::Revert(' + arg_name + ')')
    elif arg_type == 'refptr_diff':
      ptr_class = arg.get_type().get_ptr_type()
      params.append(ptr_class + 'CppToC::Invert(' + arg_name + ')')
    elif arg_type == 'refptr_same_byref' or arg_type == 'refptr_diff_byref':
      ptr_class = arg.get_type().get_ptr_type()
      ptr_struct = arg.get_type().get_result_ptr_type_root()
      if arg_type == 'refptr_same_byref':
        assign = ptr_class + 'CToCpp::Revert(' + arg_name + ')'
      else:
        assign = ptr_class + 'CppToC::Invert(' + arg_name + ')'
      result += comment + \
                '\n  ' + ptr_struct + '* ' + arg_name + 'Struct = NULL;'\
                '\n  if (' + arg_name + '.get()) {'\
                '\n    ' + arg_name + 'Struct = ' + assign + ';'\
                '\n  }'\
                '\n  ' + ptr_struct + '* ' + arg_name + 'Orig = ' + arg_name + 'Struct;'
      params.append('&' + arg_name + 'Struct')
    else:
      raise Exception('Unsupported argument type %s for parameter %s in %s' %
                      (arg_type, arg_name, name))
  return result, params

def make_ctocpp_static_vars(clsname, funcs):
  new_list = []
  old_list = make_file_base.get_func_name_list(funcs)

  impl = ''
  for func in funcs:
    suffix = ''
    new_list = make_file_base.get_func_name_count(func.get_capi_name(), old_list, new_list)
    if new_list.count(func.get_capi_name()) > 0:
      suffix = str(new_list.count(func.get_capi_name()))
    elif file_parser.check_func_name_is_key_work(func.get_capi_name()):
      suffix = '0'

    parts = func.get_capi_parts()
    static_var_type = clsname + func.get_name() + 'Func' + suffix
    static_var_name = func.get_capi_name() + suffix
    impl += 'using ' + static_var_type + ' = ' + parts['retval'] + ' (*)(' + ', '.join(parts['args']) + ');\n'\
            'static ' + static_var_type + ' ' + static_var_name + ' = nullptr;\n\n'

  return impl

def load_ctocpp_static_func(dir_name, clsname, name, func, suffix):
  retval = func.get_retval()
  retval_type = retval.get_retval_type()
  retval_default = retval.get_retval_default(False)

  static_var_type = clsname + func.get_name() + 'Func' + suffix
  static_var_name = func.get_capi_name() + suffix
  result = '\n  ARK_WEB_CTOCPP_DV_LOG();\n'\
           '\n  if(!' + static_var_name + ') {'\
           '\n    ' + static_var_name + ' = reinterpret_cast<' + static_var_type + '>('
  if dir_name == 'ohos_nweb':
    result += 'ArkWebNWebBridgeHelper'
  else:
    result += 'ArkWebAdapterBridgeHelper'
  result += '::GetInstance().LoadFuncSymbol("' + static_var_name + '_static"));'\
            '\n    if(!' + static_var_name + ') {'\
            '\n      ARK_WEB_CTOCPP_WARN_LOG("failed to get static function symbol");'\
            '\n      return ' + retval_default + ';'\
            '\n    }\n  }\n'
  return result

def make_ctocpp_function_impl_new(dir_name, clsname, name, func, suffix):
  # build the C++ prototype
  parts = func.get_cpp_parts(True)
  result = make_ctocpp_impl_proto(clsname, name, func, parts) + ' {'

  invalid = make_file_base.get_func_invalid_info(name, func)
  if len(invalid) > 0:
    return result + invalid

  if isinstance(func, file_parser.obj_function_virtual):
    result += '\n  ARK_WEB_CTOCPP_DV_LOG(\"capi struct is %{public}ld\", (long)this);\n\n'
    # determine how the struct should be referenced
    if clsname == func.parent.get_name():
      result += '  ' +  file_parser.get_capi_name(clsname, True) + '* _struct = GetStruct();'
    else:
      result += '  ' + func.parent.get_capi_name() + '* _struct = reinterpret_cast<' + \
                func.parent.get_capi_name() + '*>(GetStruct());'
  else:
    result += load_ctocpp_static_func(dir_name, clsname, name, func, suffix)

  retval = func.get_retval()
  retval_default = retval.get_retval_default(False)
  if len(retval_default) > 0:
    retval_default = ' ' + retval_default
    macro_retval_default = retval_default
  else:
    macro_retval_default = 'ARK_WEB_RETURN_VOID'

  if isinstance(func, file_parser.obj_function_virtual):
    result += '\n  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ' + macro_retval_default + ');\n'

    # add the structure size check
    result += '\n  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, ' + func.get_capi_name() + suffix + ', ' \
            + macro_retval_default + ');\n'

  result_len = len(result)

  # parameter verification
  result += verify_ctocpp_func_args(func, retval_default)
  if len(result) != result_len:
    result += '\n'
    result_len = len(result)

  # parameter translation
  trans, params = translate_ctocpp_func_args(func)
  if len(trans) != 0:
    result += trans + '\n'

  # execution
  result += '\n  // Execute\n  '

  retval_type = retval.get_retval_type()
  if retval_type != 'none':
    # has a return value
    if retval_type == 'simple' or retval_type == 'bool' or retval_type == 'void*' or retval_type == 'uint8_t*' or \
       retval_type == 'uint32_t*' or retval_type == 'char*' or file_parser.check_arg_type_is_struct(retval_type):
      result += 'return '
    elif retval_type == 'refptr_same' or retval_type == 'refptr_diff':
      ptr_struct = retval.get_type().get_result_ptr_type_root()
      result += ptr_struct + '* _retval = '
    else:
      raise Exception('Unsupported return type %s in %s' % (retval_type, name))

  if isinstance(func, file_parser.obj_function_virtual):
    result += '_struct->'
  result += func.get_capi_name() + suffix + '('

  if len(params) > 0:
    if not isinstance(func, file_parser.obj_function_virtual):
      result += '\n      '
    result += ',\n      '.join(params)

  result += ');\n'
  result_len = len(result)

  # parameter restoration
  result += restore_ctocpp_func_args(func)
  if len(result) != result_len:
    result += '\n'
    result_len = len(result)

  if retval_type == 'refptr_same':
    result += '\n  // Return type: ' + retval_type
    result += '\n  return ' + retval.get_type().get_ptr_type() + 'CToCpp::Invert(_retval);'
  elif retval_type == 'refptr_diff':
    result += '\n  // Return type: ' + retval_type
    result += '\n  return ' + retval.get_type().get_ptr_type() + 'CppToC::Revert(_retval);'

  if len(result) != result_len:
    result += '\n'

  result += '}\n\n'
  return result


def make_ctocpp_function_impl(dir_name, clsname, funcs):
  impl = ''

  new_list = []
  old_list = make_file_base.get_func_name_list(funcs)

  for func in funcs:
    suffix = ''
    new_list = make_file_base.get_func_name_count(func.get_capi_name(), old_list, new_list)
    if new_list.count(func.get_capi_name()) > 0:
      suffix = str(new_list.count(func.get_capi_name()))
    elif file_parser.check_func_name_is_key_work(func.get_capi_name()):
      suffix = '0'

    name = func.get_name()
    impl += make_ctocpp_function_impl_new(dir_name, clsname, name, func, suffix)

  return impl


def make_ctocpp_virtual_function_impl(header, cls):
  impl = ''
  parent_cls = cls
  while True:
    impl += make_ctocpp_function_impl('', cls.get_name(), parent_cls.get_virtual_funcs())

    parent_clsname = parent_cls.get_parent_name()
    if file_parser.is_base_class(parent_clsname):
      break

    parent_cls = header.get_class(parent_clsname)
    if parent_cls is None:
      raise Exception('Class does not exist: ' + parent_clsname)

  return impl


def make_ctocpp_unwrap_derived(header, cls, base_scoped):
  derived_classes = make_file_base.get_derived_classes(cls, header)

  if base_scoped:
    impl = ['', '']
    for clsname in derived_classes:
      impl[0] += '  if (type == '+file_parser.get_wrapper_type_enum(clsname)+') {\n'+\
                 '    return reinterpret_cast<'+file_parser.get_capi_name(cls.get_name(), True)+'*>('+\
                 clsname+'CToCpp::UnwrapOwn(CefOwnPtr<'+clsname+'>(reinterpret_cast<'+clsname+'*>(c.release()))));\n'+\
                 '  }\n'
      impl[1] += '  if (type == '+file_parser.get_wrapper_type_enum(clsname)+') {\n'+\
                 '    return reinterpret_cast<'+file_parser.get_capi_name(cls.get_name(), True)+'*>('+\
                 clsname+'CToCpp::UnwrapRaw(CefRawPtr<'+clsname+'>(reinterpret_cast<'+clsname+'*>(c))));\n'+\
                 '  }\n'
  else:
    impl = ''
    for clsname in derived_classes:
      impl += '  if (type == '+file_parser.get_wrapper_type_enum(clsname)+') {\n'+\
              '    return reinterpret_cast<'+file_parser.get_capi_name(cls.get_name(), True)+'*>('+\
              clsname+'CToCpp::Revert(reinterpret_cast<'+clsname+'*>(c)));\n'+\
              '  }\n'
  return impl

def make_ctocpp_impl_file(header, dir_path, dir_name, clsname):
  cls = header.get_class(clsname)
  if cls is None:
    raise Exception('Class does not exist: ' + clsname)

  capiname = cls.get_capi_name()

  base_class_name = header.get_base_class_name(clsname)
  base_scoped = True if base_class_name == 'ArkWebBaseScoped' else False
  if base_scoped:
    template_class = 'ArkWebCToCppScoped'
  else:
    template_class = 'ArkWebCToCppRefCounted'

  virtualimpl = make_ctocpp_virtual_function_impl(header, cls)
  staticparam = make_ctocpp_static_vars(clsname, cls.get_static_funcs())
  staticimpl = make_ctocpp_function_impl(dir_name, clsname, cls.get_static_funcs())
  resultingimpl = staticparam + staticimpl + virtualimpl

  unwrapderived = make_ctocpp_unwrap_derived(header, cls, base_scoped)

  const =  clsname+'CToCpp::'+clsname+'CToCpp() {\n'+ \
           '}\n\n'+ \
           clsname+'CToCpp::~'+clsname+'CToCpp() {\n'
  const += '}\n\n'

  includes = file_parser.format_translation_includes(header, dir_name, const + resultingimpl +
                                         (unwrapderived[0]
                                          if base_scoped else unwrapderived))
  includes += '#include "base/ctocpp/ark_web_ctocpp_macros.h"\n'
  if len(cls.get_static_funcs()) > 0:
    if dir_name == 'ohos_nweb':
      includes += '#include "ohos_nweb/bridge/ark_web_nweb_bridge_helper.h"\n'
    else:
      includes += '#include "ohos_adapter/bridge/ark_web_adapter_bridge_helper.h"\n'

  content = make_file_base.get_copyright()
  content += '\n' + includes + '\n' + 'namespace OHOS::ArkWeb {\n\n' + resultingimpl 

  parent_sig = template_class + '<' + clsname + 'CToCpp, ' + clsname + ', ' + capiname + '>'
  const += make_file_base.make_wrapper_type(clsname, parent_sig)

  content += const
  content += '\n\n} // namespace OHOS::ArkWeb\n'

  absolute_dir = os.path.join(os.path.join(dir_path, dir_name), 'ctocpp')
  absolute_path = os.path.join(absolute_dir, file_parser.get_capi_name(clsname, False) + '_ctocpp.cpp')

  return (content, absolute_path)
