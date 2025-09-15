import { createClient } from '@supabase/supabase-js';
import 'dotenv/config'; // Carrega as variáveis de ambiente

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
  throw new Error(
    'Supabase URL e Key são obrigatórias nas variáveis de ambiente.'
  );
}

export const supabase = createClient(supabaseUrl, supabaseKey);
