//! Embedded web console assets and routing.
//!
//! Serves a small single-page admin UI (vanilla HTML/CSS/JS) that talks to
//! the existing S3 API directly via SigV4 signed in the browser via Web
//! Crypto. The `/console/*` namespace is intercepted in `server.zig` before
//! SigV4 enforcement so the static assets are publicly fetchable while the
//! actual S3 calls the UI makes still go through normal authentication.
const std = @import("std");
const http = @import("http.zig");

const index_html = @embedFile("ui_assets/index.html");
const style_css = @embedFile("ui_assets/style.css");
const app_js = @embedFile("ui_assets/app.js");

/// True if `path` is owned by the web console and should bypass S3 routing.
pub fn matches(path: []const u8) bool {
    return std.mem.eql(u8, path, "/console") or
        std.mem.startsWith(u8, path, "/console/");
}

/// Build a 200 response for a console asset, or a 404 if `path` is unknown.
/// All bodies are static — no allocator required.
pub fn serve(path: []const u8) http.Response {
    // /console and /console/ both serve the SPA shell.
    if (std.mem.eql(u8, path, "/console") or std.mem.eql(u8, path, "/console/")) {
        return staticAsset("text/html; charset=utf-8", index_html);
    }
    if (std.mem.eql(u8, path, "/console/style.css")) {
        return staticAsset("text/css; charset=utf-8", style_css);
    }
    if (std.mem.eql(u8, path, "/console/app.js")) {
        return staticAsset("application/javascript; charset=utf-8", app_js);
    }
    return .{
        .status = 404,
        .status_text = "Not Found",
        .content_type = "text/plain; charset=utf-8",
        .body = .{ .bytes = "console asset not found" },
    };
}

fn staticAsset(content_type: []const u8, bytes: []const u8) http.Response {
    return .{
        .status = 200,
        .status_text = "OK",
        .content_type = content_type,
        .body = .{ .bytes = bytes },
    };
}

test "matches recognizes console paths" {
    try std.testing.expect(matches("/console"));
    try std.testing.expect(matches("/console/"));
    try std.testing.expect(matches("/console/app.js"));
    try std.testing.expect(!matches("/consoleX"));
    try std.testing.expect(!matches("/my-bucket"));
    try std.testing.expect(!matches("/"));
}

test "serve returns assets" {
    const r1 = serve("/console");
    try std.testing.expectEqual(@as(u16, 200), r1.status);
    try std.testing.expect(std.mem.startsWith(u8, r1.content_type, "text/html"));

    const r2 = serve("/console/app.js");
    try std.testing.expectEqual(@as(u16, 200), r2.status);

    const r3 = serve("/console/missing");
    try std.testing.expectEqual(@as(u16, 404), r3.status);
}
