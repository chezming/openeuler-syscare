#!/bin/bash
#SPDX-License-Identifier: Mulan-PSL2.0

set -e

readonly SCRIPT_NAME=$(basename "$0")
readonly PATCH_INSTALL_DIR="/usr/lib/syscare/patches"
readonly SYSCARE_PATCH_BUILD="/usr/libexec/syscare/syscare-build"
readonly UPATCH_TOOL="/usr/libexec/syscare/upatch-tool"
readonly RECORD_FILE="/usr/lib/syscare/patch-record"

PATCH_LIST=""
PATCH_NAME=""
PATCH_PKG=""
PATCH_TYPE=""
PATCH_STATUS=""
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
	[ -d "$1" ] || return 0
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
	local has_pkg_name=$(echo $1 | grep "/")

	if [ "${has_pkg_name}" == "" ];then
		for patch_record in ${PATCH_LIST}; do
			local name=$(echo "${patch_record}" | awk -F ',' '{print $2}')
			local dir=$(echo "${patch_record}" | awk -F ',' '{print $3}')

			if [ "${name}" == "${patch_name}" ]; then
				echo "${dir}"
				break
			fi
		done
	else
		local dir="${PATCH_INSTALL_DIR}/${patch_name}"
		if [ -e "${dir}" ];then
			echo "${dir}"
		fi
	fi
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
		echo "Patch version mismatches with patch version."
		return 1
	fi

	return 0
}

function do_build() {
	if [ ! -f "${SYSCARE_PATCH_BUILD}" ]; then
		echo "syscare-build is not installed."
		echo "You can install syscare-build rpm to enable build function."
		return 1
	fi

	"${SYSCARE_PATCH_BUILD}" "$@"
}

function apply_patch() {
	if  [ "${PATCH_TYPE}" == "kernel" ] ; then
		check_kversion || return 1
		[ "${PATCH_STATUS}" == "NOT-APPLIED" ] && insmod "${PATCH_ROOT}/${PATCH_NAME}.ko" || return 1
		PATCH_STATUS="DEACTIVED"
		active_patch || return 1
	else
		"${UPATCH_TOOL}" apply -b "${ELF_PATH}" -p "${PATCH_ROOT}/${PATCH_NAME}" || return 1
	fi

	local patch_name=$(grep "name:${PATCH_PKG}/${PATCH_NAME} " ${RECORD_FILE} | awk '{print $1}' | awk -F: '{print $2}')
	if [ "${PATCH_PKG}/${PATCH_NAME}" != "${patch_name}" ]; then
		echo "name:${PATCH_PKG}/${PATCH_NAME} isactive:1" >> ${RECORD_FILE}
	fi
}

function remove_patch() {
	if [ "${PATCH_TYPE}" == "kernel" ] ; then
		[ "${PATCH_STATUS}" == "NOT-APPLIED" ] && return
		[ "${PATCH_STATUS}" == "ACTIVED" ] && deactive_patch
		rmmod "${PATCH_NAME}" || return 1
	else
		"${UPATCH_TOOL}" remove -b "${ELF_PATH}"
	fi

	sed -i "/name:${PATCH_PKG}\/${PATCH_NAME} /d" ${RECORD_FILE}
}

function active_patch() {
	if [ "${PATCH_STATUS}" == "NOT-APPLIED" ]; then
		echo "patch ${PATCH_PKG}/${PATCH_NAME} is not applied"
		return 1
	fi

	if [ "${PATCH_TYPE}" == "kernel" ] ; then
		[ "${PATCH_STATUS}" == "DEACTIVED" ] && echo 1 > "${KPATCH_STATE_FILE}"
	else
		"${UPATCH_TOOL}" active -b "${ELF_PATH}"
	fi

	sed -i "/name:${PATCH_PKG}\/${PATCH_NAME} /c\name:${PATCH_PKG}\/${PATCH_NAME} isactive:1" ${RECORD_FILE}
}

function deactive_patch() {
	if [ "${PATCH_STATUS}" == "NOT-APPLIED" ]; then
		echo "patch ${PATCH_PKG}/${PATCH_NAME} is not applied"
		return 1
	fi

	if [ "${PATCH_TYPE}" == "kernel" ] ; then
			[ "${PATCH_STATUS}" == "ACTIVED" ] && echo 0 > "${KPATCH_STATE_FILE}"
	else
		"${UPATCH_TOOL}" deactive -b "$ELF_PATH"
	fi

	sed -i "/name:${PATCH_PKG}\/${PATCH_NAME} /c\name:${PATCH_PKG}\/${PATCH_NAME} isactive:0" ${RECORD_FILE}
}

function patch_status() {
	local patch_name="$1"

	initialize_patch_info ${patch_name} || return 1

	echo "${PATCH_STATUS}"
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
	local has_pkg_name=$(echo $1 | grep "/")

	if [ ! -e "${RECORD_FILE}" ]; then
		touch "${RECORD_FILE}"
	fi

	if [ ! -d "${patch_root}" ]; then
		echo "${SCRIPT_NAME}: cannot find patch '${patch_name}'" >&2
		return 1
	fi

	if [ "${has_pkg_name}" == "" ];then
		PATCH_NAME="${patch_name}"
		for patch_record in ${PATCH_LIST}; do
			local name=$(echo "${patch_record}" | awk -F ',' '{print $2}')
			local pkg=$(echo "${patch_record}" | awk -F ',' '{print $1}')

			if [ "${name}" == "${patch_name}" ]; then
				PATCH_PKG="${pkg}"
				break
			fi
		done
	else
		PATCH_NAME=$(echo "${patch_name}" | awk -F '/' '{print $2}')
		PATCH_PKG=$(echo "${patch_name}" | awk -F '/' '{print $1}')
	fi

	PATCH_ROOT=$(get_patch_root_by_patch_name "${patch_name}")
	PATCH_TYPE=$(get_patch_type "${patch_name}")
	ELF_PATH=$(get_patch_elf_path "${patch_name}")
	if [ "${PATCH_TYPE}" == "kernel" ]; then
		KPATCH_MODULE_NAME="${PATCH_NAME//-/_}"
		KPATCH_STATE_FILE="/sys/kernel/livepatch/${KPATCH_MODULE_NAME}/enabled"
	fi

	# get patch status
	if [ "${PATCH_TYPE}" == "kernel" ]; then
		if [ ! -f "${KPATCH_STATE_FILE}" ]; then
			PATCH_STATUS="NOT-APPLIED"
			return
		fi

		if [ $(cat "${KPATCH_STATE_FILE}") -eq 1 ]; then
			PATCH_STATUS="ACTIVED"
		else
			PATCH_STATUS="DEACTIVED"
		fi
	else
		local state=$("${UPATCH_TOOL}" info -p "${PATCH_ROOT}/${PATCH_NAME}" 2>/dev/null | grep Status | awk -F ':' '{print $2}')
		state=$(eval echo "${state}")
		if [ "${state}" == "actived" ]; then
			PATCH_STATUS="ACTIVED"
		elif [ "${state}" == "removed" ]; then
			PATCH_STATUS="NOT-APPLIED"
		else
			PATCH_STATUS="DEACTIVED"
		fi
	fi
}

function do_apply() {
	if [ "$#" -ne 1 ]; then
		echo "syscare: Invalid Parameters, use \"syscare apply [pkg-name/]<patch-name>\""
		exit 1
	fi

	initialize_patch_list
	initialize_patch_info "$1" || return 1
	apply_patch
}

function do_active() {
	if [ "$#" -ne 1 ]; then
		echo "syscare: Invalid Parameters, use \"syscare active [pkg-name/]<patch-name>\""
		exit 1
	fi

	initialize_patch_list
	initialize_patch_info "$1" || return 1
	active_patch
}

function do_deactive() {
	if [ "$#" -ne 1 ]; then
		echo "syscare: Invalid Parameters, use \"syscare deactive [pkg-name/]<patch-name>\""
		exit 1
	fi

	initialize_patch_list
	initialize_patch_info "$1" || return 1
	deactive_patch
}

function do_remove() {
	if [ "$#" -ne 1 ]; then
		echo "syscare: Invalid Parameters, use \"syscare remove [pkg-name/]<patch-name>\""
		exit 1
	fi

	initialize_patch_list
	initialize_patch_info "$1" || return 1
	remove_patch
}

function do_list() {
	if [ "$#" -gt 0 ]; then
		echo "syscare: Too many parameters, just use \"syscare list\""
		exit 1
	fi

	initialize_patch_list
	show_patch_list
}

function do_status() {
	if [ "$#" -ne 1 ]; then
		echo "syscare: Invalid Parameters, use \"syscare status [pkg-name/]<patch-name>\""
		exit 1
	fi

	initialize_patch_list
	initialize_patch_info "$1" || return 1
	echo "${PATCH_STATUS}"
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
			do_build "$@"
			;;
		apply	|--apply-patch)
			shift
			do_apply "$@"
			;;
		active	|--active-patch)
			shift
			do_active "$@"
			;;
		deactive	|--deactive-patch)
			shift
			do_deactive "$@"
			;;
		remove	|--remove-patch)
			shift
			do_remove "$@"
			;;
		list	|--all-patch)
			shift
			do_list "$@"
			;;
		status	|--patch-status)
			shift
			do_status "$@"
			;;
		*)
			echo "${SCRIPT_NAME}: Command not found, use --help to get usage." >&2
	esac
}

main "$@"
