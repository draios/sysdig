/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <memory>
#include <string>

#include "cri.pb.h"
#include "cri.grpc.pb.h"

#include "container_info.h"

namespace libsinsp {
namespace cri {
extern std::string s_cri_unix_socket_path;
extern std::unique_ptr<runtime::v1alpha2::RuntimeService::Stub> s_cri;
extern std::unique_ptr<runtime::v1alpha2::ImageService::Stub> s_cri_image;
extern int64_t s_cri_timeout;
extern sinsp_container_type s_cri_runtime_type;
extern bool s_cri_extra_queries;

sinsp_container_type get_cri_runtime_type(const std::string &runtime_name);

bool parse_cri_image(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info &container);

bool parse_cri_mounts(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info &container);

bool parse_cri_env(const Json::Value &info, sinsp_container_info &container);

bool parse_cri_json_image(const Json::Value &info, sinsp_container_info *container);

bool parse_cri_runtime_spec(const Json::Value &info, sinsp_container_info *container);

bool is_pod_sandbox(const std::string &container_id);

uint32_t get_pod_sandbox_ip(const std::string &pod_sandbox_id);

uint32_t get_container_ip(const std::string &container_id);

std::string get_container_image_id(const std::string &image_ref);
}
}
