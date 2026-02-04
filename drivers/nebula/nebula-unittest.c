/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2021 GoldenRiver Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>

#include "nebula-unittest.h"

/**
 * \brief Function called to dump results
 *
 * This function will call the out_func callback
 */
int unittest_printf(const char *format, ...)
{
	int ret = 0;
	char buf[256];

	va_list argp;
	va_start(argp, format);
	ret = vsnprintf(buf, sizeof(buf), format, argp);
	va_end(argp);

	pr_info("%s", buf);
	return ret;
}
EXPORT_SYMBOL(unittest_printf);

bool unittest_expect_bytes(const void *expected, const char *expected_name,
			   const void *actual, const char *actual_name,
			   size_t len, const char *msg, const char *func,
			   int line, bool expect_eq)
{
	if (!memcmp(expected, actual, len) != expect_eq) {
		unittest_printf(UNITTEST_FAIL_TRACEF_FORMAT
				"%s:\n        %s %s %s, but %s!\n",
				func, line, msg, expected_name,
				expect_eq ? "does not match" : "matches",
				actual_name,
				expect_eq ? "should" : "should not");

		unittest_printf("  expected (%s)\n", expected_name);
		print_hex_dump(KERN_INFO, KBUILD_MODNAME ":     ",
			       DUMP_PREFIX_ADDRESS, 16, 1, expected, len, true);

		unittest_printf("  actual (%s)\n", actual_name);
		print_hex_dump(KERN_INFO, KBUILD_MODNAME ":     ",
			       DUMP_PREFIX_ADDRESS, 16, 1, actual, len, true);

		return false;
	}
	return true;
}
EXPORT_SYMBOL(unittest_expect_bytes);

// External references to the testcase registration tables.
extern unittest_testcase_registration_t __start_unittest_testcases[];
extern unittest_testcase_registration_t __stop_unittest_testcases[];

static int _run_unittest(const unittest_testcase_registration_t *testcase)
{
	size_t i;
	char fmt_string[32];
	char out_string[64];
	size_t max_namelen = 0;
	size_t passed = 0;
	bool good;
	const unittest_registration_t *test;
	ktime_t testcase_start;
	ktime_t test_start;
	ktime_t test_runtime;
	ktime_t testcase_runtime;

	for (i = 0; i < testcase->test_cnt; ++i) {
		test = &testcase->tests[i];
		if (test->name) {
			size_t namelen = strlen(test->name);
			if (max_namelen < namelen)
				max_namelen = namelen;
		}
	}
	snprintf(fmt_string, sizeof(fmt_string), "  %%-%zus : ", max_namelen);

	unittest_printf("%s : Running %zu test%s...\n", testcase->name,
			testcase->test_cnt, testcase->test_cnt == 1 ? "" : "s");

	testcase_start = ktime_get();

	for (i = 0; i < testcase->test_cnt; ++i) {
		test = &testcase->tests[i];

		memset(out_string, 0, sizeof(out_string));
		snprintf(out_string, sizeof(out_string), fmt_string,
			 test->name ? test->name : "");

		test_start = ktime_get();
		good = test->fn ? test->fn() : false;
		test_runtime = ktime_sub(ktime_get(), test_start);

		if (good) {
			passed++;
		}

		unittest_printf("%s%s (%lld nSec)\n", out_string,
				good ? "PASSED" : "FAILED",
				ktime_to_ns(test_runtime));
	}

	testcase_runtime = ktime_sub(ktime_get(), testcase_start);

	unittest_printf("%s : %sll tests passed (%zu/%zu) in %lld nSec\n",
			testcase->name,
			passed != testcase->test_cnt ? "Not a" : "A", passed,
			testcase->test_cnt, ktime_to_ns(testcase_runtime));

	return passed == testcase->test_cnt;
}

static void _run_unittests(const char *casename)
{
	const unittest_testcase_registration_t *testcase;

	for (testcase = __start_unittest_testcases;
	     testcase != __stop_unittest_testcases; ++testcase) {
		if (testcase->name && !strcmp(casename, testcase->name)) {
			_run_unittest(testcase);
			return;
		}
	}

	unittest_printf("Test case \"%s\" not found!\n", casename);
}

static int _unittest_show(struct seq_file *m, void *v)
{
	char fmt_string[32];
	size_t count = 0;
	size_t max_namelen = 0;

	const unittest_testcase_registration_t *testcase;
	for (testcase = __start_unittest_testcases;
	     testcase != __stop_unittest_testcases; ++testcase) {
		if (testcase->name) {
			size_t namelen = strlen(testcase->name);
			if (max_namelen < namelen)
				max_namelen = namelen;
			count++;
		}
	}

	seq_printf(m, "There %s %zu test case%s available...\n",
		   count == 1 ? "is" : "are", count, count == 1 ? "" : "s");
	snprintf(fmt_string, sizeof(fmt_string), "  %%-%zus : %%s\n",
		 max_namelen);

	for (testcase = __start_unittest_testcases;
	     testcase != __stop_unittest_testcases; ++testcase) {
		if (testcase->name)
			seq_printf(m, fmt_string, testcase->name,
				   testcase->desc ? testcase->desc :
							  "<no description>");
	}

	return 0;
}

static ssize_t _unittest_write(struct file *filp, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	size_t len;
	char name[32];

	len = min(count, sizeof(name) - 1);
	if (copy_from_user(name, buf, len))
		return -EFAULT;

	while (len > 0 && name[len - 1] == '\n')
		len--;
	name[len] = '\0';

	_run_unittests(name);

	return count;
}

static int _unittest_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, _unittest_show, inode->i_private);
}

static const struct file_operations _unittest_fops = {
	.open = _unittest_open,
	.release = single_release,
	.read = seq_read,
	.write = _unittest_write,
	.owner = THIS_MODULE,
};

int nebula_unittest_init(void)
{
	struct dentry *debugfs_root;
	const char *dev_name = "nebula";

	debugfs_root = debugfs_create_dir(dev_name, NULL);
	if (IS_ERR(debugfs_root)) {
		pr_err("debugfs_create_dir failed: %ld\n",
		       PTR_ERR(debugfs_root));
		return PTR_ERR(debugfs_root);
	}

	debugfs_create_file("unittest", 0600, debugfs_root, NULL,
			    &_unittest_fops);

	return 0;
}
late_initcall(nebula_unittest_init);

static bool dummy_passed_unittest1(void)
{
	BEGIN_TEST;

	EXPECT_EQ(0, 0, "");

	END_TEST;
}

static bool dummy_passed_unittest2(void)
{
	BEGIN_TEST;

	int a[] = { 0xdada, 0xdbdb, 0xdcdc, 0xdddd, 0xdede };
	int b[] = { 0xdada, 0xdbdb, 0xdcdc, 0xdddd, 0xdedf };
	EXPECT_BYTES_NE(&a, &b, sizeof(a), "msg");

	END_TEST;
}
UNITTEST_START_TESTCASE(dummy_passed)
UNITTEST(dummy_passed_unittest1)
UNITTEST(dummy_passed_unittest2)
UNITTEST_END_TESTCASE(dummy_passed, "An example of passed testcase");

static bool dummy_failed_unittest1(void)
{
	BEGIN_TEST;

	EXPECT_EQ(0, 1, "");

	END_TEST;
}

static bool dummy_failed_unittest2(void)
{
	BEGIN_TEST;

	int a[] = { 0xdada, 0xdbdb, 0xdcdc, 0xdddd, 0xdede };
	int b[] = { 0xdada, 0xdbdb, 0xdcdc, 0xdddd, 0xdedf };
	EXPECT_BYTES_EQ(&a, &b, sizeof(a), "");

	END_TEST;
}
UNITTEST_START_TESTCASE(dummy_failed)
UNITTEST(dummy_failed_unittest1)
UNITTEST(dummy_failed_unittest2)
UNITTEST_END_TESTCASE(dummy_failed, "An example of failed testcase");
