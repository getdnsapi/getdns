/**
 * \file
 * \brief display messages to support unit testing
 */
/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TESTMESSAGES_H
#define TESTMESSAGES_H 1

/**
 * call at the start of a test program to display start message
 */
void tstmsg_prog_begin(char *prognm);
/**
 * call at the end of a test program to display end message
 */
void tstmsg_prog_end();

/**
 * call at the start of a test case (after test_prog_begin)
 * to display case start message
 */
void tstmsg_case_begin(char *casenm);
/**
 * call at the end of a test case (after test_prog_begin/test_case_begin)
 * to display case end message
 */
void tstmsg_case_end();

/**
 * call to display message regarding the current test case
 * to display case end message
 * TODO: add macro to automatically output source file line
 */
void tstmsg_case_msg(char *msg);

#endif

/* testmessages.h */
