load("@com_google_protobuf//:protobuf.bzl", "py_proto_library")

cc_library(
    name = "libprotobuf_mutator_internals",
    srcs = [
        "src/binary_format.cc",
        "src/field_instance.h",
        "src/libfuzzer/libfuzzer_macro.cc",
        "src/libfuzzer/libfuzzer_mutator.cc",
        "src/mutator.cc",
        "src/text_format.cc",
        "src/utf8_fix.cc",
        "src/weighted_reservoir_sampler.h",
    ],
    hdrs = [
        "port/protobuf.h",
        "src/binary_format.h",
        "src/libfuzzer/libfuzzer_macro.h",
        "src/libfuzzer/libfuzzer_mutator.h",
        "src/mutator.h",
        "src/random.h",
        "src/text_format.h",
        "src/utf8_fix.h",
    ],
    includes = [
        ".",
    ],
    deps = [
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "libprotobuf_mutator",
    hdrs = [
        "src/libfuzzer/libfuzzer_macro.h",
    ],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        ":libprotobuf_mutator_internals",
    ],
)

py_proto_library(
    name = "mutator_test_py_pb2",
    srcs = [
        "src/mutator_test_proto2.proto",
        "src/mutator_test_proto3.proto",
    ],
    deps = ["@com_google_protobuf//:protobuf_python"],
    visibility = ["//visibility:public"],
)
