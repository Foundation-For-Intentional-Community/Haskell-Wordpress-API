augroup project
    au BufRead,BufNewFile *.hs let g:ale_fixers = {'haskell': ['remove_trailing_lines', 'trim_whitespace', 'brittany']}
augroup END
