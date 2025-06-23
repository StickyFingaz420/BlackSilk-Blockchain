#!/bin/bash

echo "🔧 Building ML-DSA-44 Rust wrapper..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi

echo ""
echo "🧪 Running tests..."
cargo test

if [ $? -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed!"
    exit 1
fi

echo ""
echo "📚 Running doc tests..."
cargo test --doc

if [ $? -eq 0 ]; then
    echo "✅ Doc tests passed!"
else
    echo "❌ Doc tests failed!"
    exit 1
fi

echo ""
echo "📖 Generating documentation..."
cargo doc --no-deps

echo ""
echo "🎉 All checks completed successfully!"
echo ""
echo "📁 Project structure:"
find . -name "*.rs" -o -name "*.toml" -o -name "*.md" | head -10