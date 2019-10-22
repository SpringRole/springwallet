const path = require('path');
const webpack = require('webpack');
const config = {
    entry: './src/springwallet.js',
    output: {
        path: path.resolve(__dirname, './dist'),
        filename: 'springwallet.web.js',
        libraryTarget: 'global',
        library: 'SpringWallet',
        libraryExport: 'default'
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
    },
    plugins: [new webpack.IgnorePlugin(/^\.\/wordlists\/(?!english)/, /bip39\/src$/)]
};

module.exports = config;
