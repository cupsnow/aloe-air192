const path = require('path');
const { merge } = require('webpack-merge');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const TerserPlugin = require("terser-webpack-plugin");

let cfg = {
  entry: path.join(__dirname,'src','admin.js'),
  output: {
    path: path.join(__dirname,'build'),
    filename: 'admin.bundle.js'
  },
  mode: process.env.NODE_ENV || 'development',
  resolve: {
    modules: [path.resolve(__dirname, 'src'), 'node_modules']
  },
  module: {
    rules: [
      {
        test: /\.jsx?$/,
        exclude: /(node_modules|bower_components)/,
        use: [
          {
            loader: 'babel-loader',
            options: {
              cacheDirectory: true,
              presets: ['@babel/env', '@babel/react'],
              plugins: ['@babel/plugin-proposal-class-properties']
            }
          }
          // {loader: 'eslint-loader'}
        ]
      },
      {
        test: /\.s?css$/,
        use: [
          "style-loader", // creates style nodes from JS strings
          "css-loader", // translates CSS into CommonJS
          "sass-loader" // compiles Sass to CSS, using Node Sass by default          }
        ]
      },
      {
        test: /\.(jpe?g|png|svg|gif)$/,
        use: [
          {
            loader: 'url-loader',
            options: {limit: 4000}
          }
        ]
      },
      {
        test: /admin.ejs$/,
        loader: 'ejs-loader',
        options: {
          esModule: false
        }
      }
    ]
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: path.join(__dirname,'src','admin.ejs'),
      title: 'Air192 Management'
    })
  ]
};

cfg = merge(cfg, process.env.NODE_ENV === 'production' ?
  {

  } :
  {
    devtool: 'source-map',
    devServer: {
      static: {
        directory: path.join(__dirname,'src'),
      },
      host: "0.0.0.0",
      port: 8765,
      hot: true
    },
  });

module.exports = cfg;
