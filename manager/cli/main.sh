#!/bin/bash
#SPDX-License-Identifier: Mulan-PSL2.0

set -e

readonly SCRIPT_NAME=$(basename "$0")
readonly PATCH_INSTALL_DIR="/usr/lib/syscare/patches"
readonly SYSCARE_PATCH_BUILD="/usr/libexec/syscare/syscare-build"
readonly UPATCH_TOOL="/usr/libexec/syscare/upatch-tool"

PATCH_LIST=""
PATCH_NAME=""
PATCH_TYPE=""
ELF_PATH=""
KPATCH_MODULE_NAME=""
KPATCH_STATE_FILE=""

function check_root_user() {
	if [ "$(whoami)" == "root" ]; then
		return 0
	else
		echo "${SCRIPT_NAME}: needs to be root" >&2
		return 1
	fi
}

function list_all_path() {
	local search_dir="$1"
	if [ ! -d "${search_dir}" ]; then
		echo "'${search_dir}' is not a directory" >&2
		return 1
	fi

	for path in $(ls -lA $(realpath "${search_dir}") | awk -F ' ' '{print $NF}' | tail -n +2); do
		realpath "${search_dir}/${path}"
	done
}

function list_all_directoies() {
	for path in $(list_all_path "$1"); do
		if [ -d "${path}" ]; then
			echo "${path}"
		fi
	done
}

function list_all_files() {
	for path in $(list_all_path "$1"); do
		if [ -f "${path}" ]; then
			echo "${path}"
		fi
	done
}

function fetch_patch_list() {
	for pkg_path in $(list_all_directoies "$1"); do
		local pkg_name=$(basename "${pkg_path}")

		for patch_path in $(list_all_directoies "${pkg_path}"); do
			local patch_name=$(basename "${patch_path}")
			local patch_info_path="${patch_path}/patch_info";

			if [ -f "${patch_info_path}" ]; then
				echo "${pkg_name},${patch_name},${patch_path}"
			fi
		done
	done
}

function is_patch_exist() {
	local patch_name="$1"

	for patch_record in ${PATCH_LIST}; do
		local record_patch_name=$(echo "${patch_record}" | awk -F ',' '{print $2}')
		if [ "${record_patch_name}" == "${patch_name}" ]; then
			return 0
		fi
	done

	return 1
}

function show_patch_list() {
	printf "%-35s %-25s %-8s\n" "PackageName" "PatchName" "PatchStatus"
	for patch_record in ${PATCH_LIST}; do
		local pkg_name=$(echo "${patch_record}" | awk -F ',' '{print $1}')
		local patch_name=$(echo "${patch_record}" | awk -F ',' '{print $2}')
		local patch_status=$(patch_status "${patch_name}")
		printf "%-35s %-25s %-8s\n" "${pkg_name}" "${patch_name}" "${patch_status}"
	done
}

function get_patch_root_by_pkg_name() {
	local pkg_name="$1"

	for patch_record in ${PATCH_LIST}; do
		local name=$(echo "${patch_record}" | awk -F ',' '{print $1}')
		local dir=$(echo "${patch_record}" | awk -F ',' '{print $3}')

		if [ "${name}" == "${pkg_name}" ]; then
			echo "${dir}"
		fi
	done
}

function get_patch_root_by_patch_name() {
	local patch_name="$1"

	for patch_record in ${PATCH_LIST}; do
		local name=$(echo "${patch_record}" | awk -F ',' '{print $2}')
		local dir=$(echo "${patch_record}" | awk -F ',' '{print $3}')

		if [ "${name}" == "${patch_name}" ]; then
			echo "${dir}"
		fi
	done
}

function get_patch_type() {
	local patch_name="$1"
	local patch_root=$(get_patch_root_by_patch_name "${patch_name}")
	local patch_type=$(cat "${patch_root}/patch_info" | grep "type" | awk -F ':' '{print $2}' | xargs echo -n)

	if [ "${patch_type}" == "KernelPatch" ]; then
		echo "kernel"
	else
		echo "user"
	fi
}

function get_patch_elf_path() {
	[ "${PATCH_TYPE}" == "kernel" ] && return

	local patch_name="$1"
	local patch_root=$(get_patch_root_by_patch_name "${patch_name}")
	local package_name=$(cat "${patch_root}/patch_info" | grep target | awk -F ':' '{print $2}' | xargs echo -n)
	local binary_name=$(cat "${patch_root}/patch_info" | grep elf_name | awk -F ':' '{print $2}' | xargs echo -n)

	echo $(rpm -ql "${package_name}" | grep "\/${binary_name}$" | xargs file | grep ELF | awk  -F: '{print $1}')
}

function check_kversion() {
	[ "${PATCH_TYPE}" == "kernel" ] || return 0

	local kv=$(uname -r)
	local kernel_version="kernel-"${kv%.*}
	local patch_version=$(cat "${PATCH_ROOT}/patch_info" | grep "target" | awk -F ':' '{print $2}' | xargs echo -n)
	if [ "${kernel_version}" != "${patch_version}" ]; then
		echo "Patch version mismatches with patch version." >&2
		return 1
	fi

	return 0
}

function check_kpatched() {
	lsmod | grep -q -w "${KPATCH_MODULE_NAME}" > /dev/null

	if [ $? -eq 0 ]; then
		return 0
	fi
	return 1
}

function build_patch() {
	"${SYSCARE_PATCH_BUILD}" $@
}

function apply_patch() {
	is_patch_exist "${PATCH_NAME}" || return 1

	if  [ "${PATCH_TYPE}" == "kernel" ] ; then
		check_kpatched || insmod "${PATCH_ROOT}/${PATCH_NAME}.ko"
		active_patch
		return
	else
		"${UPATCH_TOOL}" apply -b "${ELF_PATH}" -p "${PATCH_ROOT}/${PATCH_NAME}"
	fi
}

function remove_patch() {
	is_patch_exist "${PATCH_NAME}" || return 1

	if [ "${PATCH_TYPE}" == "kernel" ] ; then
		check_kversion || return 1

		[ -f "${KPATCH_STATE_FILE}" ] || return 1

		if [ $(cat "${KPATCH_STATE_FILE}") -eq 1 ]; then
			echo "patch is in use"
			return
	 	else
			rmmod "${PATCH_NAME}"
			return
		fi
	else
		"${UPATCH_TOOL}" remove -b "${ELF_PATH}"
	fi
}

function active_patch() {
	is_patch_exist "${PATCH_NAME}" || return 1

	if [ "${PATCH_TYPE}" == "kernel" ] ; then
		check_kversion || return 1
		[ -f "${KPATCH_STATE_FILE}" ] || return 1

		if [ $(cat "${KPATCH_STATE_FILE}") -eq 1 ] ; then
			return
		else
			echo 1 > "${KPATCH_STATE_FILE}"
			return
		fi
	else
		"${UPATCH_TOOL}" active -b "${ELF_PATH}"
	fi
}

function deactive_patch() {
	is_patch_exist "${PATCH_NAME}" || return 1

	if [ "${PATCH_TYPE}" == "kernel" ] ; then
		check_kversion || return 1
		[ -f "${KPATCH_STATE_FILE}" ] || return 1

		if [ $(cat "${KPATCH_STATE_FILE}") -eq 0 ] ; then
			return
		else
			echo 0 > "${KPATCH_STATE_FILE}"
			return
		fi
	else
		"${UPATCH_TOOL}" deactive -b "$ELF_PATH"
	fi
}

function patch_status() {
	local patch_name="$1"
	local patch_type=$(get_patch_type "${patch_name}")

	initialize_patch_info ${patch_name}
	is_patch_exist "${patch_name}" || return 1

	if [ "${patch_type}" == "kernel" ]; then
		if [ ! -f "${KPATCH_STATE_FILE}" ]; then
			echo "DEACTIVE"
			return
		fi

		if [ $(cat "${KPATCH_STATE_FILE}") -eq 1 ]; then
			echo "ACTIVE"
		else
			echo "DEACTIVE"
		fi
	else
		local state=$("${UPATCH_TOOL}" info -p "${PATCH_ROOT}/${PATCH_NAME}" | grep Status | awk -F ':' '{print $2}')
		state=$(eval echo "${state}")
		if [ "${state}" == "actived" ]; then
			echo "ACTIVE"
		else
			echo "DEACTIVE"
		fi
	fi
}

function usage() {
	echo -e "\033[1;4mUsage:\033[0m \033[1m${SCRIPT_NAME}\033[0m <command> [<args>]" >&2
	echo "  " >&2
	echo -e "\033[1;4mCommand:\033[0m"
	echo -e "  \033[1mbuild\033[0m                           Build patch, for more information, please run '${SCRIPT_NAME} build --help'" >&2
	echo -e "  \033[1mlist\033[0m                            Query local patched list" >&2
	echo -e "  \033[1mapply\033[0m <patch-name>              Apply patch into the running kernel or process" >&2
	echo -e "  \033[1mactive\033[0m <patch-name>             Activate patch into the running kernel or process" >&2
	echo -e "  \033[1mdeactive\033[0m <patch-name>           Deactive patch" >&2
	echo -e "  \033[1mremove\033[0m <patch-name>             Remove the patch in kernel or process" >&2
	echo -e "  \033[1m-h, --help\033[0m                      Show this help message" >&2
}

function initialize_patch_list() {
	check_root_user || exit 1

	PATCH_LIST=$(fetch_patch_list "${PATCH_INSTALL_DIR}")
}

function initialize_patch_info() {
	local patch_name="$1"
	local patch_root=$(get_patch_root_by_patch_name "${patch_name}")

	if [ ! -d "${patch_root}" ]; then
		echo "${SCRIPT_NAME}: cannot find patch '${patch_name}'" >&2
		return 1
	fi

	PATCH_NAME="${patch_name}"
	PATCH_ROOT=$(get_patch_root_by_patch_name "${patch_name}")
	PATCH_TYPE=$(get_patch_type "${patch_name}")
	ELF_PATH=$(get_patch_elf_path "${patch_name}")
	if [ "${PATCH_TYPE}" == "kernel" ]; then
		KPATCH_MODULE_NAME="${PATCH_NAME//-/_}"
		KPATCH_STATE_FILE="/sys/kernel/livepatch/${KPATCH_MODULE_NAME}/enabled"
	fi
}

function main() {
	if [[ $# -lt 1 ]]; then
		usage
		exit 1
	fi

	case "$1" in
		help	|-h	|--help)
			usage
			exit 0
			;;
		build	|--build-patch)
			shift
			build_patch $@
			;;
		apply	|--apply-patch)
			initialize_patch_list
			initialize_patch_info "$2"
			apply_patch
			;;
		active	|--active-patch)
			initialize_patch_list
			initialize_patch_info "$2"
			active_patch
			;;
		deactive	|--deactive-patch)
			initialize_patch_list
			initialize_patch_info "$2"
			deactive_patch
			;;
		remove	|--remove-patch)
			initialize_patch_list
			initialize_patch_info "$2"
			remove_patch
			;;
		list	|--all-patch)
			initialize_patch_list
			show_patch_list
			;;
		status	|--patch-status)
			initialize_patch_list
			initialize_patch_info "$2"
			patch_status "$2"
			;;
		*)
			echo "${SCRIPT_NAME}: command not found, use --help to get usage." >&2
	esac
}

main $@
