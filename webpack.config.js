const webpack = require('webpack');

const libraryName = 'SpringWallet';

const webConfig = {
    entry: `${__dirname}/src/index.js`,
    target: 'web',
    output: {
        path: `${__dirname}/dist`,
        filename: `${libraryName}.umd.js`,
        library: libraryName,
        libraryTarget: 'umd',
        libraryExport: 'default',
        umdNamedDefine: true
    },
    module: {
        rules: [{test: /\.js$/, exclude: /node_modules/, loader: 'babel-loader'}]
    },
    resolve: {
        alias: {
            scrypt: `${__dirname}/node_modules/scrypt.js`
        }
    },
    plugins: [new webpack.IgnorePlugin(/^\.\/wordlists\/(?!english)/, /bip39\/src$/)]
};

const nodeConfig = {
    ...webConfig,
    target: 'node',
    output: {
        path: `${__dirname}/dist`,
        filename: `${libraryName}.node.js`,
        library: libraryName,
        libraryExport: 'default',
        libraryTarget: 'commonjs2'
    }
};

module.exports = [webConfig, nodeConfig];
