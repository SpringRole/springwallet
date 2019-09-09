const path = require('path');
const config = {
    entry: './src/index.js',
    target: 'web',
    output: {
        path: path.resolve(__dirname, './dist'),
        filename: 'springwallet.js'
    },
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ['@babel/preset-env']
                    }
                }
            }
        ]
    }
};

module.exports = config;
