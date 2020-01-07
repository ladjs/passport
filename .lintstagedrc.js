module.exports = {
  '*.md' : [
    filenames => filenames.map(filename => `remark ${filename} -qfo`),
    'git add'
  ],
  'package.json': ['fixpack', 'git add'],
  '*.js': ['xo --fix', 'git add ']
};
