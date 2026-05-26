def sum_array (arr: []i64) : i64 =
  reduce (+) 0 arr

def map_add (arr: []i64) (value: i64) : []i64 =
  map (\x -> x + value) arr

def map_multiply (arr: []i64) (factor: i64) : []i64 =
  map (\x -> x * factor) arr

def filter_positive (arr: []i64) : []i64 =
  filter (\x -> x > 0) arr

def dot_product [n] (a: [n]i64) (b: [n]i64) : i64 =
  reduce (+) 0 (map2 (*) a b)

def vector_add [n] (a: [n]i64) (b: [n]i64) : [n]i64 =
  map2 (+) a b

def vector_sub [n] (a: [n]i64) (b: [n]i64) : [n]i64 =
  map2 (-) a b

def vector_scale (arr: []i64) (scalar: i64) : []i64 =
  map (\x -> x * scalar) arr

def find_max (arr: []i64) : i64 =
  reduce i64.max i64.lowest arr

def find_min (arr: []i64) : i64 =
  reduce i64.min i64.highest arr

def count_positive (arr: []i64) : i64 =
  reduce (+) 0i64 (map (\x -> if x > 0i64 then 1i64 else 0i64) arr)

def sum_matrix (mat: [][]i64) : i64 =
  reduce (+) 0 (map (reduce (+) 0) mat)

def map_matrix (mat: [][]i64) (value: i64) : [][]i64 =
  map (map (\x -> x + value)) mat

def matrix_transpose [n][m] (mat: [n][m]i64) : [m][n]i64 =
  transpose mat

def matrix_multiply [m][n][p] (a: [m][n]i64) (b: [n][p]i64) : [m][p]i64 =
  map (\ar ->
    map (\bc ->
      reduce (+) 0 (map2 (*) ar bc)
    ) (transpose b)
  ) a

def prefix_sum (arr: []i64) : []i64 =
  scan (+) 0 arr

def scatter_array (dest: []i64) (indices: []i64) (values: []i64) : []i64 =
  scatter (copy dest) indices values

def gather (src: []i64) (indices: []i64) : []i64 =
  map (\i -> src[i]) indices

def partition_array (arr: []i64) (pivot: i64) : ([]i64, []i64) =
  let left = filter (\x -> x <= pivot) arr
  let right = filter (\x -> x > pivot) arr
  in (left, right)

def histogram (arr: []i64) (num_bins: i64) : []i64 =
  if num_bins <= 0 || length arr == 0
  then replicate 0 0i64
  else
    let min_val = find_min arr
    let max_val = find_max arr
    let range = max_val - min_val
    in if range == 0
       then
         let result = replicate num_bins 0i64
         let result = result with [0] = i64.i64 (length arr)
         in result
       else
         let bin_size = (range + num_bins - 1) / num_bins
         in loop acc = replicate num_bins 0i64 for x in arr do
              let raw_bin = (x - min_val) / bin_size
              let clamped_bin =
                if raw_bin < 0 then 0
                else if raw_bin >= num_bins then num_bins - 1
                else raw_bin
              in acc with [clamped_bin] = acc[clamped_bin] + 1i64

def flatten_matrix (mat: [][]i64) : []i64 =
  flatten mat

def flatten_3d (arr: [][][]i64) : []i64 =
  flatten (flatten arr)

def zip_arrays [n] (a: [n]i64) (b: [n]i64) : [n](i64, i64) =
  zip a b

def unzip_array [n] (arr: [n](i64, i64)) : ([]i64, []i64) =
  unzip arr

def all_equal (arr: []i64) : bool =
  if length arr == 0
  then true
  else
    let first = arr[0]
    in reduce (&&) true (map (\x -> x == first) arr)

def any_positive (arr: []i64) : bool =
  reduce (||) false (map (\x -> x > 0) arr)

def all_positive (arr: []i64) : bool =
  reduce (&&) true (map (\x -> x > 0) arr)

def replicate_array (n: i64) (value: i64) : []i64 =
  replicate n value

def iota_array (n: i64) : []i64 =
  iota n

def update_array (arr: []i64) (index: i64) (value: i64) : []i64 =
  arr with [index] = value

def update_matrix (mat: [][]i64) (row: i64) (col: i64) (value: i64) : [][]i64 =
  let updated_row = mat[row] with [col] = value
  in mat with [row] = updated_row

def mean_array (arr: []f64) : f64 =
  let n = length arr
  in if n == 0
     then 0.0
     else reduce (+) 0.0 arr / f64.i64 n

def variance_array (arr: []f64) : f64 =
  let n = length arr
  in if n == 0
     then 0.0
     else
       let mean = mean_array arr
       in reduce (+) 0.0 (map (\x -> (x - mean) * (x - mean)) arr) / f64.i64 n

def std_dev_array (arr: []f64) : f64 =
  f64.sqrt (variance_array arr)

def normalize_array (arr: []f64) : []f64 =
  let mean = mean_array arr
  let std = std_dev_array arr
  in if std == 0.0
     then map (\_ -> 0.0) arr
     else map (\x -> (x - mean) / std) arr

def min_max_normalize (arr: []f64) : []f64 =
  let min_val = reduce f64.min f64.highest arr
  let max_val = reduce f64.max f64.lowest arr
  let range = max_val - min_val
  in if range == 0.0
     then map (\_ -> 0.0) arr
     else map (\x -> (x - min_val) / range) arr

def euclidean_distance [n] (a: [n]f64) (b: [n]f64) : f64 =
  f64.sqrt (reduce (+) 0.0 (map (\x -> x * x) (map2 (-) a b)))

def cosine_similarity [n] (a: [n]f64) (b: [n]f64) : f64 =
  let dot = reduce (+) 0.0 (map2 (*) a b)
  let mag_a = f64.sqrt (reduce (+) 0.0 (map (\x -> x * x) a))
  let mag_b = f64.sqrt (reduce (+) 0.0 (map (\x -> x * x) b))
  let denom = mag_a * mag_b
  in if denom == 0.0
     then 0.0
     else dot / denom

def softmax (arr: []f64) : []f64 =
  if length arr == 0
  then []
  else
    let max_val = reduce f64.max f64.lowest arr
    let exp_vals = map (\x -> f64.exp (x - max_val)) arr
    let sum_exp = reduce (+) 0.0 exp_vals
    in if sum_exp == 0.0
       then map (\_ -> 0.0) exp_vals
       else map (\x -> x / sum_exp) exp_vals

def relu (arr: []f64) : []f64 =
  map (\x -> if x > 0.0 then x else 0.0) arr

def sigmoid (arr: []f64) : []f64 =
  map (\x ->
    if x >= 0.0
    then 1.0 / (1.0 + f64.exp (-x))
    else
      let e = f64.exp x
      in e / (1.0 + e)
  ) arr

def tanh_array (arr: []f64) : []f64 =
  map f64.tanh arr

def leaky_relu (arr: []f64) (alpha: f64) : []f64 =
  map (\x -> if x > 0.0 then x else alpha * x) arr

def elu (arr: []f64) (alpha: f64) : []f64 =
  map (\x -> if x > 0.0 then x else alpha * (f64.exp x - 1.0)) arr

def convolve_1d (signal: []f64) (kernel: []f64) : []f64 =
  let n = length signal
  let k = length kernel
  in if k > n
     then []
     else
       map (\i ->
         reduce (+) 0.0 (map (\j -> signal[i + j] * kernel[k - 1 - j]) (iota k))
       ) (iota (n - k + 1))

def moving_average (arr: []f64) (window: i64) : []f64 =
  let n = length arr
  in if window <= 0 || window > n
     then []
     else
       map (\i ->
         reduce (+) 0.0 (map (\j -> arr[i + j]) (iota window)) / f64.i64 window
       ) (iota (n - window + 1))

def exponential_moving_average (arr: []f64) (alpha: f64) : []f64 =
  if length arr == 0
  then []
  else
    scan (\acc x -> alpha * x + (1.0 - alpha) * acc) arr[0] arr

def find_peaks (arr: []f64) (threshold: f64) : []i64 =
  let n = length arr
  in if n < 3
     then []
     else
       filter (\i ->
         i > 0 && i < n - 1 && arr[i] > arr[i-1] && arr[i] > arr[i+1] && arr[i] > threshold
       ) (iota n)

def main : i64 =
  0i64
