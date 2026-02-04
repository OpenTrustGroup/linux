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

#ifndef __LINUX_NEBULA_UNITTEST_H
#define __LINUX_NEBULA_UNITTEST_H

#include <linux/kernel.h>
#include <linux/types.h>

/*
 * Printf dedicated to the unittest library
 * the default output is the printf
 */
int unittest_printf(const char* format, ...);

/*
 * Macros to format the error string
 */
#define EXPECTED_STRING "%s:\n        expected "
#define UNITTEST_FAIL_TRACEF_FORMAT "\n        [FAILED]\n        %s:%d:\n        "
#define UNITTEST_FAIL_TRACEF(str, x...)                                        \
    do {                                                                       \
        unittest_printf(UNITTEST_FAIL_TRACEF_FORMAT str,                       \
                        __PRETTY_FUNCTION__, __LINE__, ##x);                   \
    } while (0)

/*
 * BEGIN_TEST and END_TEST go in a function that is called by RUN_TEST
 * and that call the EXPECT_ macros.
 */

#define BEGIN_TEST bool all_ok = true
#define END_TEST return all_ok

#ifdef __cplusplus
#define AUTO_TYPE_VAR(type) auto&
#else
#define AUTO_TYPE_VAR(type) __typeof__(type)
#endif

/*
 * UTCHECK_* macros are used to check test results.  Generally, one should
 * prefer to use either the EXPECT_* (non-terminating) or ASSERT_*
 * (terminating) forms of the macros.  See below.
 */
#define UTCHECK_EQ(expected, actual, msg, term)                                \
    do {                                                                       \
        const AUTO_TYPE_VAR(expected) _e = (expected);                         \
        const AUTO_TYPE_VAR(actual) _a = (actual);                             \
        if (_e != _a) {                                                        \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING                               \
                            "%s (%ld), "                                       \
                            "actual %s (%ld)\n",                               \
                            msg, #expected, (long)_e, #actual, (long)_a);      \
            if (term) return false; else all_ok = false;                       \
        }                                                                      \
    } while (0)

#define UTCHECK_NE(expected, actual, msg, term)                                \
    do {                                                                       \
        const AUTO_TYPE_VAR(expected) _e = (expected);                         \
        if (_e == (actual)) {                                                  \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING                               \
                            "%s (%ld), %s"                                     \
                            " to differ, but they are the same %ld\n",         \
                            msg, #expected, (long)_e, #actual);                \
            if (term) return false; else all_ok = false;                       \
        }                                                                      \
    } while (0)

#define UTCHECK_LE(expected, actual, msg, term)                                \
    do {                                                                       \
        const AUTO_TYPE_VAR(expected) _e = (expected);                         \
        const AUTO_TYPE_VAR(actual) _a = (actual);                             \
        if (_e > _a) {                                                         \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING                               \
                            "%s (%ld) to be"                                   \
                            " less-than-or-equal-to actual %s (%ld)\n",        \
                            msg, #expected, (long)_e, #actual, (long)_a);      \
            if (term) return false; else all_ok = false;                       \
        }                                                                      \
    } while (0)

#define UTCHECK_LT(expected, actual, msg, term)                                \
    do {                                                                       \
        const AUTO_TYPE_VAR(expected) _e = (expected);                         \
        const AUTO_TYPE_VAR(actual) _a = (actual);                             \
        if (_e >= _a) {                                                        \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING                               \
                            "%s (%ld) to be"                                   \
                            " less-than actual %s (%ld)\n",                    \
                            msg, #expected, (long)_e, #actual, (long)_a);      \
            if (term) return false; else all_ok = false;                       \
        }                                                                      \
    } while (0)

#define UTCHECK_GE(expected, actual, msg, term)                                \
    do {                                                                       \
        const AUTO_TYPE_VAR(expected) _e = (expected);                         \
        const AUTO_TYPE_VAR(actual) _a = (actual);                             \
        if (_e < _a) {                                                         \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING                               \
                            "%s (%ld) to be"                                   \
                            " greater-than-or-equal-to actual %s (%ld)\n",     \
                            msg, #expected, (long)_e, #actual, (long)_a);      \
            if (term) return false; else all_ok = false;                       \
        }                                                                      \
    } while (0)

#define UTCHECK_GT(expected, actual, msg, term)                                \
    do {                                                                       \
        const AUTO_TYPE_VAR(expected) _e = (expected);                         \
        const AUTO_TYPE_VAR(actual) _a = (actual);                             \
        if (_e <= _a) {                                                        \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING                               \
                            "%s (%ld) to be"                                   \
                            " greater-than actual %s (%ld)\n",                 \
                            msg, #expected, (long)_e, #actual, (long)_a);      \
            if (term) return false; else all_ok = false;                       \
        }                                                                      \
    } while (0)

#define UTCHECK_TRUE(actual, msg, term)                                        \
    if (!(actual)) {                                                           \
        UNITTEST_FAIL_TRACEF("%s: %s is false\n", msg, #actual);               \
        if (term) return false; else all_ok = false;                           \
    }

#define UTCHECK_FALSE(actual, msg, term)                                       \
    if (actual) {                                                              \
        UNITTEST_FAIL_TRACEF("%s: %s is true\n", msg, #actual);                \
        if (term) return false; else all_ok = false;                           \
    }

#define UTCHECK_NULL(actual, msg, term)                                        \
    if (actual != NULL) {                                                      \
        UNITTEST_FAIL_TRACEF("%s: %s is non-null!\n", msg, #actual);           \
        if (term) return false; else all_ok = false;                           \
    }

#define UTCHECK_NONNULL(actual, msg, term)                                     \
    if (actual == NULL) {                                                      \
        UNITTEST_FAIL_TRACEF("%s: %s is null!\n", msg, #actual);               \
        if (term) return false; else all_ok = false;                           \
    }

#define UTCHECK_BYTES_EQ(expected, actual, length, msg, term)                  \
    if (!unittest_expect_bytes((expected), #expected,                          \
                               (actual), #actual,                              \
                               (length), msg, __PRETTY_FUNCTION__, __LINE__,   \
                               true)) {                                        \
        if (term) return false; else all_ok = false;                           \
    }

#define UTCHECK_BYTES_NE(expected, actual, length, msg, term)                  \
    if (!unittest_expect_bytes((expected), #expected,                          \
                               (actual), #actual,                              \
                               (length), msg, __PRETTY_FUNCTION__, __LINE__,   \
                               false)) {                                       \
        if (term) return false; else all_ok = false;                           \
    }

/* EXPECT_* macros check the supplied condition and will print a message and flag the test
 * as having failed if the condition fails.  The test will continue to run, even
 * if the condition fails.
 */
#define EXPECT_EQ(expected, actual, msg)               UTCHECK_EQ(expected, actual, msg, false)
#define EXPECT_NE(expected, actual, msg)               UTCHECK_NE(expected, actual, msg, false)
#define EXPECT_LE(expected, actual, msg)               UTCHECK_LE(expected, actual, msg, false)
#define EXPECT_LT(expected, actual, msg)               UTCHECK_LT(expected, actual, msg, false)
#define EXPECT_GE(expected, actual, msg)               UTCHECK_GE(expected, actual, msg, false)
#define EXPECT_GT(expected, actual, msg)               UTCHECK_GT(expected, actual, msg, false)
#define EXPECT_TRUE(actual, msg)                       UTCHECK_TRUE(actual, msg, false)
#define EXPECT_FALSE(actual, msg)                      UTCHECK_FALSE(actual, msg, false)
#define EXPECT_BYTES_EQ(expected, actual, length, msg) UTCHECK_BYTES_EQ(expected, actual, length, msg, false)
#define EXPECT_BYTES_NE(bytes1, bytes2, length, msg)   UTCHECK_BYTES_NE(bytes1, bytes2, length, msg, false)
#define EXPECT_NULL(actual, msg)                       UTCHECK_NULL(actual, msg, false)
#define EXPECT_NONNULL(actual, msg)                    UTCHECK_NONNULL(actual, msg, false)

/* ASSERT_* macros check the condition and will print a message and immediately
 * abort a test with a filure status if the condition fails.
 */
#define ASSERT_EQ(expected, actual, msg)               UTCHECK_EQ(expected, actual, msg, true)
#define ASSERT_NE(expected, actual, msg)               UTCHECK_NE(expected, actual, msg, true)
#define ASSERT_LE(expected, actual, msg)               UTCHECK_LE(expected, actual, msg, true)
#define ASSERT_LT(expected, actual, msg)               UTCHECK_LT(expected, actual, msg, true)
#define ASSERT_GE(expected, actual, msg)               UTCHECK_GE(expected, actual, msg, true)
#define ASSERT_GT(expected, actual, msg)               UTCHECK_GT(expected, actual, msg, true)
#define ASSERT_TRUE(actual, msg)                       UTCHECK_TRUE(actual, msg, true)
#define ASSERT_FALSE(actual, msg)                      UTCHECK_FALSE(actual, msg, true)
#define ASSERT_BYTES_EQ(expected, actual, length, msg) UTCHECK_BYTES_EQ(expected, actual, length, msg, true)
#define ASSERT_BYTES_NE(bytes1, bytes2, length, msg)   UTCHECK_BYTES_NE(bytes1, bytes2, length, msg, true)
#define ASSERT_NULL(actual, msg)                       UTCHECK_NULL(actual, msg, true)
#define ASSERT_NONNULL(actual, msg)                    UTCHECK_NONNULL(actual, msg, true)

/*
 * Returns false if expected does or does not equal actual (based on expect_eq).
 * Will print msg and a hexdump8 of the input buffers if the check fails.
 */
bool unittest_expect_bytes(const void* expected,
                           const char* expected_name,
                           const void* actual,
                           const char* actual_name,
                           size_t len,
                           const char *msg,
                           const char* func,
                           int line,
                           bool expect_eq);

typedef bool (*unitest_fn_t)(void);

typedef struct unitest_registration {
	const char *name;
	unitest_fn_t fn;
} unittest_registration_t;

typedef struct unitest_testcase_registration {
	const char *name;
	const char *desc;
	const unittest_registration_t *tests;
	size_t test_cnt;
} unittest_testcase_registration_t;

#define UNITTEST_START_TESTCASE(_global_id)                                    \
	static const unittest_registration_t __unittest_table_##_global_id[] = {
#define UNITTEST(_fn) { .name = #_fn, .fn = _fn },

#define UNITTEST_END_TESTCASE(_global_id, _desc)                               \
	}                                                                      \
	; /* __unittest_table_##_global_id */                                  \
	static const unittest_testcase_registration_t                          \
		__unittest_case_##_global_id __used                            \
		__attribute__((__section__(".nbl.unittest_testcases"))) = {    \
			.name = #_global_id,                                   \
			.desc = _desc,                                         \
			.tests = __unittest_table_##_global_id,                \
			.test_cnt = ARRAY_SIZE(__unittest_table_##_global_id), \
		}

#endif /* __LINUX_NEBULA_UNITTEST_H */
