package camoproxy

import (
  "testing"
  "bytes"
)

/* Tests the Write on CSSReWriter does what we expect */
func TestCSSReWriter(t *testing.T) {
  // Some setup...
  writer := bytes.NewBufferString("")
  rewriter, _ := NewHttpReWriter(writer)
  // No rewrite, should flush immediately...
  not_http := []byte("htpp://")
  rewriter.Write(not_http)
  got := writer.Bytes()
  if bytes.Compare(got, not_http) == 1 {
    t.Errorf("Got %v for output, expected %v", string(got), string(not_http))
  }
  writer.Reset()
  // http away from boundary, should replace and flush immediately...
  input := []byte("http://example.com")
  expected := []byte("https://example.com")
  rewriter.Write(input)
  got = writer.Bytes()
  if bytes.Compare(got, []byte("https://example.com")) == 1 {
    t.Errorf("Got %v for output, expected %v", string(got), string(expected))
  }
  writer.Reset()
  // http at boundary, should wait for more input...
  input = []byte("example http:")
  rewriter.Write(input)
  got = writer.Bytes()
  if bytes.Compare(got, []byte("")) == 1 {
    t.Errorf("Got %v for output, expected empty bytes", string(got))
  }
  // Push some more into it, we should flush
  input = []byte("//example.com")
  rewriter.Write(input)
  got = writer.Bytes()
  expected = []byte("example https://example.com")
  if bytes.Compare(got, expected) == 1 {
    t.Errorf("Got %v for output, expected %v", string(got), string(expected))
  }
}
